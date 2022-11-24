import {KeeperSecrets} from './keeper'
import {webSafe64ToBytes} from './utils'

type KeeperField = {
    type: string
    label?: string
    value: any[]
}

// deprecated - Use this instead: import {getNotationResults} from './keeper'
export function getValue(secrets: KeeperSecrets, notation: string): any {
    const schemaNotation = notation.split('://')
    if (schemaNotation.length > 1) {
        if (schemaNotation[0] !== 'keeper') {
            throw Error(`Invalid notation schema: ${schemaNotation[0]}`)
        }
        notation = notation.slice(9)
    }
    const notationParts = notation.split('/')
    if (notationParts.length < 3) {
        throw Error(`Invalid notation ${notation}`)
    }
    const record = secrets.records.find(x => x.recordUid === notationParts[0])
    if (!record) {
        throw Error(`Record ${notationParts[0]} not found`)
    }
    let fields: KeeperField[]
    switch (notationParts[1]) {
        case 'field':
            fields = record.data.fields
            break
        case 'custom_field':
            fields = record.data.custom
            break
        case 'file':
            const fileId = notationParts[2]
            const file = (record.files || []).find(x => x.data.title === fileId || x.data.name === fileId)
            if (!file) {
                throw Error(`File ${fileId} not found in the record ${record.recordUid}`)
            }
            return file
        default:
            throw Error(`Expected /field or /custom_field but found /${notationParts[1]}`)
    }

    const findField = (fieldName: string): KeeperField => {
        const field = fields.find(x => x.label === fieldName || x.type === fieldName)
        if (!field) {
            throw Error(`Field ${fieldName} not found in the record ${record.recordUid}`)
        }
        return field
    }

    if (notationParts[2].endsWith('[]')) {
        return findField(notationParts[2].slice(0, -2)).value
    }
    const fieldParts = notationParts[2]
        .replace(/[\[\]]/g, '/')
        .split('/')
        .filter(x => x)
    const field = findField(fieldParts[0])
    if (fieldParts.length === 1) {
        return field.value[0]
    }
    const fieldValueIdx = parseInt(fieldParts[1])
    if (isNaN(fieldValueIdx)) {
        return field.value[0][fieldParts[1]]
    }
    if (fieldValueIdx < 0 || fieldValueIdx >= field.value.length) {
        throw Error(`The index ${fieldValueIdx} for field value of ${fieldParts[0]} in the record ${record.recordUid} is out of range (${field.value.length - 1})`)
    }
    return fieldParts.length === 2
        ? field.value[fieldValueIdx]
        : field.value[fieldValueIdx][fieldParts[2]]
}

// data class to represent parsed notation section
type StringTuple = [string, string]
class NotationSection {
    section: string     // section name - ex. prefix
    isPresent: boolean  // presence flag
    startPos: number    // section start position in URI
    endPos: number      // section end position in URI
    text: StringTuple | null        // <unescaped, raw> text
    parameter: StringTuple | null   // <field type>|<field label>|<file name>
    index1: StringTuple | null      // numeric index [N] or []
    index2: StringTuple | null      // property index - ex. field/name[0][middle]
    constructor(sectionName: string) {
        this.section = sectionName
        this.isPresent = false
        this.startPos = -1
        this.endPos = -1
        this.text = null
        this.parameter = null
        this.index1 = null
        this.index2 = null
    }
}

const EscapeChar: number = '\\'.charCodeAt(0)
const EscapeChars: string = '/[]\\' // /[]\ -> \/ ,\[, \], \\
// Escape the characters in plaintext sections only - title, label or filename

function parseSubsection(text: string, pos: number, delimiters: string, escaped: boolean = false): StringTuple|null {
    // raw string excludes start delimiter (if '/') but includes end delimiter or both (if '[',']')
    if (!text || pos < 0 || pos >= text.length)
        return null
    if (!delimiters || delimiters.length > 2)
        throw new Error(`Notation parser: Internal error - Incorrect delimiters count. Delimiters: '${delimiters}'`)

    let token = ''
    let raw = ''
    while (pos < text.length) {
        if (escaped && EscapeChar == text.charCodeAt(pos)) {
            // notation cannot end in single char incomplete escape sequence
            // and only escape_chars should be escaped
            if (((pos + 1) >= text.length) || !EscapeChars.includes(text[pos + 1]))
                throw new Error(`Notation parser: Incorrect escape sequence at position ${pos}`)
            // copy the properly escaped character
            token += text[pos + 1]
            raw += text[pos] + text[pos + 1]
            pos += 2
        } else { // escaped == false || EscapeChar != text.charCodeAt(pos)
            raw += text[pos] // delimiter is included in raw text
            if (delimiters.length == 1) {
                if (text[pos] == delimiters[0])
                    break
                else
                    token += text[pos]
            } else { // 2 delimiters
                if (raw[0] != delimiters[0])
                    throw new Error(`Notation parser: Index sections must start with '['`)
                if (raw.length > 1 && text[pos] == delimiters[0])
                    throw new Error(`Notation parser: Index sections do not allow extra '[' inside.`)
                if (!delimiters.includes(text[pos]))
                    token += text[pos]
                else if (text[pos] == delimiters[1])
                    break
            }
            pos++
        }
    }
    //pos = (pos < text.length) ? pos : text.length - 1
    if (delimiters.length == 2 && (
        (raw.length < 2 || raw[0] != delimiters[0] || raw[raw.length - 1] != delimiters[1]) ||
        (escaped && raw.charCodeAt(raw.length - 2) == EscapeChar)))
    throw new Error(`Notation parser: Index sections must be enclosed in '[' and ']'`)

    const result: StringTuple = [token, raw]
    return result
}

function parseSection(notation: string, section: string, pos: number): NotationSection {
    if (!notation)
        throw new Error(`Keeper notation parsing error - missing notation URI`)

    const sectionName = section.toLowerCase()
    const sections = ['prefix', 'record', 'selector', 'footer']
    if (!sections.includes(sectionName))
        throw new Error(`Keeper notation parsing error - unknown section: '${sectionName}'`)

    const result = new NotationSection(section)
    result.startPos = pos

    switch (sectionName) {
        case 'prefix': {
            // prefix 'keeper://' is not mandatory
            const uriPrefix: string = 'keeper://'
            if (notation.toLowerCase().startsWith(uriPrefix)) {
                result.isPresent = true
                result.startPos = 0
                result.endPos = uriPrefix.length - 1
                result.text = [notation.substring(0, uriPrefix.length), notation.substring(0, uriPrefix.length)]
            }
            break
        }
        case 'footer': {
            // footer should not be present - used only for verification
            result.isPresent = (pos < notation.length)
            if (result.isPresent) {
                result.startPos = pos
                result.endPos = notation.length - 1
                result.text = [notation.substring(pos), notation.substring(pos)]
            }
            break
        }
        case 'record': {
            // record is always present - either UID or title
            result.isPresent = (pos < notation.length)
            if (result.isPresent)
            {
                const parsed = parseSubsection(notation, pos, '/', true)
                if (parsed != null)
                {
                    result.startPos = pos
                    result.endPos = pos + parsed[1].length - 1
                    result.text = parsed
                }
            }
            break
        }
        case 'selector': {
            // selector is always present - type|title|notes | field|custom_field|file
            result.isPresent = (pos < notation.length)
            if (result.isPresent) {
                let parsed = parseSubsection(notation, pos, '/', false)
                if (parsed != null) {
                    result.startPos = pos
                    result.endPos = pos + parsed[1].length - 1
                    result.text = parsed

                    // selector.parameter - <field type>|<field label> | <file name>
                    // field/name[0][middle], custom_field/my label[0][middle], file/my file[0]
                    const longSelectors = ['field', 'custom_field', 'file']
                    if (longSelectors.includes(parsed[0].toLowerCase())) {
                        // TODO: File metadata extraction: ex. filename[1][size] - that requires filename to be escaped
                        parsed = parseSubsection(notation, result.endPos + 1, '[', true)
                        if (parsed != null) {
                            result.parameter = parsed // <field type>|<field label> | <filename>
                            const plen = parsed[1].length - (parsed[1].endsWith('[') && !parsed[1].endsWith('\\[') ? 1 : 0)
                            result.endPos += plen

                            parsed = parseSubsection(notation, result.endPos + 1, '[]', true)
                            if (parsed != null) {
                                result.index1 = parsed // selector.index1 [int] or []
                                result.endPos += parsed[1].length
                                parsed = parseSubsection(notation, result.endPos + 1, '[]', true)
                                if (parsed != null)
                                {
                                    result.index2 = parsed // selector.index2 [str]
                                    result.endPos += parsed[1].length
                                }
                            }
                        }
                    }
                }
            }
            break
        }
        default: throw new Error(`Keeper notation parsing error - unknown section: ${sectionName}`)
    }

    return result
}

export function parseNotation(notation: string, legacyMode: boolean = false): NotationSection[] {
    if (!notation)
        throw new Error('Keeper notation is missing or invalid.')

    // Notation is either plaintext keeper URI format or URL safe base64 string (UTF8)
    // auto detect format - '/' is not part of base64 URL safe alphabet
    if (!notation.includes('/')) {
        try {
            var bytes = webSafe64ToBytes(notation)
            var plaintext = new TextDecoder('utf-8').decode(bytes)
            notation = plaintext
        }
        catch (Exception) {
            throw new Error('Keeper notation is in invalid format - plaintext URI or URL safe base64 string expected.')
        }
    }

    const prefix = parseSection(notation, 'prefix', 0) // keeper://
    let pos = (prefix.isPresent ? prefix.endPos + 1 : 0) // prefix is optional
    const record = parseSection(notation, 'record', pos) // <UID> or <Title>
    pos = (record.isPresent ? record.endPos + 1 : notation.length) // record is required
    const selector = parseSection(notation, 'selector', pos) // type|title|notes | field|custom_field|file
    pos = (selector.isPresent ? selector.endPos + 1 : notation.length) // selector is required, indexes are optional
    const footer = parseSection(notation, 'footer', pos) // Any text after the last section

    // verify parsed query
    // prefix is optional, record UID/Title and selector are mandatory
    const shortSelectors = ['type', 'title', 'notes']
    const fullSelectors = ['field', 'custom_field', 'file']
    const selectors = ['type', 'title', 'notes', 'field', 'custom_field', 'file']
    if (!record.isPresent || !selector.isPresent)
        throw new Error('Keeper notation URI missing information about the uid, file, field type, or field key.')
    if (footer.isPresent)
        throw new Error('Keeper notation is invalid - extra characters after last section.')
    if (selector.text == null || !selectors.includes(selector.text[0].toLowerCase()))
        throw new Error('Keeper notation is invalid - bad selector, must be one of (type, title, notes, field, custom_field, file).')
    if (selector.text != null && shortSelectors.includes(selector.text[0].toLowerCase()) && selector.parameter != null)
        throw new Error('Keeper notation is invalid - selectors (type, title, notes) do not have parameters.')
    if (selector.text != null && fullSelectors.includes(selector.text[0].toLowerCase())) {
        if (selector.parameter == null)
            throw new Error('Keeper notation is invalid - selectors (field, custom_field, file) require parameters.')
        if ('file' == selector.text[0].toLowerCase() && (selector.index1 != null || selector.index2 != null))
            throw new Error('Keeper notation is invalid - file selectors don\'t accept indexes.')
        if ('file' != selector.text[0].toLowerCase() && selector.index1 == null && selector.index2 != null)
            throw new Error('Keeper notation is invalid - two indexes required.')
        if (selector.index1 != null && !/^\[\d*\]$/.test(selector.index1[1]))
        {
            if (!legacyMode)
                throw new Error('Keeper notation is invalid - first index must be numeric: [n] or [].')
            if (selector.index2 == null)
            {   // in legacy mode convert /name[middle] to name[][middle]
                selector.index2 = selector.index1
                selector.index1 = ['', '[]']
            }
        }
    }

    const result: NotationSection[] = [prefix, record, selector, footer]
    return result
}

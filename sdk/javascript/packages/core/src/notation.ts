import {KeeperSecrets} from "./keeper";

type KeeperField = {
    type: string
    label?: string
    value: any[]
}

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
    };

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
        : field.value[fieldValueIdx][fieldParts[2]];
}

import {
    KeeperSecrets,
    getValue,
    parseNotation
} from '../'

const recordUID = 'k9qMpcO0aszz9w3li5XbaQ'

const secrets: KeeperSecrets = {
    appData: {
        title: "",
        type: ""
    },
    records: [
        {
            recordUid: recordUID,
            revision: 0,
            data: {
                title: 'My Record 1',
                type: 'login',
                fields: [
                    {type: 'login', value: ['My Login 1']},
                    {type: 'password', value: ['My Password 1']}
                ],
                custom: [
                    {type: 'text', label: 'My Custom 1', value: ['custom1']},
                    {type: 'text', label: 'My Custom 1', value: ['custom1']},
                    {type: 'text', label: 'My Custom 2', value: ['one', 'two', 'three']},
                    {
                        type: 'phone', label: 'phone', value: [
                            {number: '555-5555555', ext: '55'},
                            {number: '777-7777777', ext: '77'},
                            {number: '888-8888888', ext: '', 'type': 'Home'},
                            {number: '999-9999999', type: 'Work'}
                        ]
                    },
                    {
                        type: 'name', label: 'name', value: [{
                            first: 'Jenny',
                            middle: 'X',
                            last: 'Smith'
                        }]
                    },
                ]
            },
            files: [
                {
                    fileUid: 'HKGdx7dSrtuTfA67wiEZkw',
                    data: {
                        name: 'qr.png',
                        size: 53926,
                        title: 'QR Code',
                        lastModified: 1629142801191,
                        type: 'image/png'
                    },
                    url: 'QR Code File Url'
                }
            ]
        }
    ]
}

test('Notations', async () => {
    let value

    value = getValue(secrets, `keeper://${recordUID}/field/login`)
    expect(value).toBe('My Login 1')

    value = getValue(secrets, `${recordUID}/field/login`)
    expect(value).toBe('My Login 1')

    value = getValue(secrets, `keeper://${recordUID}/field/login[0]`)
    expect(value).toBe('My Login 1')

    try {
        value = getValue(secrets, `keeper://${recordUID}/field/login[1]`)
        fail('Getting wrong index did not throw')
    } catch ({message}) {
        expect(message).toContain(`Notation error - Field index out of bounds`)
    }

    value = getValue(secrets, `keeper://${recordUID}/field/login[]`)
    expect(value).toStrictEqual(['My Login 1'])

    value = getValue(secrets, `keeper://${recordUID}/custom_field/My Custom 1`)
    expect(value).toBe('custom1')

    value = getValue(secrets, `keeper://${recordUID}/custom_field/My Custom 2`)
    expect(value).toBe('one')

    value = getValue(secrets, `keeper://${recordUID}/custom_field/My Custom 2[1]`)
    expect(value).toBe('two')

    value = getValue(secrets, `keeper://${recordUID}/custom_field/My Custom 2[]`)
    expect(value).toStrictEqual(['one','two','three'])

    value = getValue(secrets, `keeper://${recordUID}/custom_field/phone[0][number]`)
    expect(value).toBe('555-5555555')

    value = getValue(secrets, `keeper://${recordUID}/custom_field/phone[1][number]`)
    expect(value).toBe('777-7777777')

    value = getValue(secrets, `keeper://${recordUID}/custom_field/phone[2]`)
    expect(value).toStrictEqual({number: "888-8888888", ext: "", type: "Home"})

    value = getValue(secrets, `keeper://${recordUID}/custom_field/name[first]`)
    expect(value).toBe('Jenny')

    value = getValue(secrets, `keeper://${recordUID}/custom_field/name[last]`)
    expect(value).toBe('Smith')

    value = getValue(secrets, `keeper://${recordUID}/file/QR Code`)
    expect(value.fileUid).toBe('HKGdx7dSrtuTfA67wiEZkw')
    expect(value.url).toBe('QR Code File Url')

    value = getValue(secrets, `keeper://${recordUID}/file/qr.png`)
    expect(value.fileUid).toBe('HKGdx7dSrtuTfA67wiEZkw')
    expect(value.url).toBe('QR Code File Url')
})

test('NotationParser', () => {
    try {
        parseNotation("/file"); // file requires parameters
        fail('Parsing bad notation did not throw')
    } catch {}

    try {
        parseNotation("/type/extra"); // extra characters after last section
        fail('Parsing bad notation did not throw')
    } catch {}

    let res = parseNotation("/type")
    expect(res[2].text?.[0]).toBe("type")

    res = parseNotation("/title")
    expect(res[2].text?.[0]).toBe("title")

    res = parseNotation("/notes")
    expect(res[2].text?.[0]).toBe("notes")

    res = parseNotation("/file/filename.ext")
    expect(res[2].text?.[0]).toBe("file")
    expect(res[2].parameter?.[0]).toBe("filename.ext")

    res = parseNotation("/field/text")
    expect(res[2].text?.[0]).toBe("field")
    expect(res[2].parameter?.[0]).toBe("text")

    res = parseNotation(String.raw`/custom_field/label with \[[0][middle]`)
    expect(res[1].text?.[0]).toBe("") // empty title
    expect(res[2].text?.[0]).toBe("custom_field")
    expect(res[2].parameter?.[0]).toBe("label with [")
    expect(res[2].index1?.[0]).toBe("0")
    expect(res[2].index2?.[0]).toBe("middle")

    res = parseNotation(String.raw`title with \[\]\//custom_field/label with \[[0][middle]`)
    expect(res[1].text?.[0]).toBe("title with []/")
    expect(res[2].text?.[0]).toBe("custom_field")
    expect(res[2].parameter?.[0]).toBe("label with [")
    expect(res[2].index1?.[0]).toBe("0")
    expect(res[2].index2?.[0]).toBe("middle")
})

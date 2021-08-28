import {
    KeeperSecrets,
    getValue
} from '../'

const recordUID = 'k9qMpcO0aszz9w3li5XbaQ'

const secrets: KeeperSecrets = {
    records: [
        {
            recordUid: recordUID,
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
            }
        }
    ]
}

test('Notations', () => {
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
    } catch (e) {
        expect(e.message).toContain(`The index 1 for field value of login in the record ${recordUID} is out of range`)
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
})
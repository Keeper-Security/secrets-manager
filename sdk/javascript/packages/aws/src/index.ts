import {KeyValueStorage, platform} from '@keeper/secrets-manager-core';
import * as AWS from "aws-sdk";
import {GetParameterRequest, PutParameterRequest, DeleteParametersRequest} from "aws-sdk/clients/ssm";

export const createAwsKeyValueStorage = (): KeyValueStorage => {

    const getValue = (key: string): Promise<string | undefined> => {
        const ssm = new AWS.SSM();
        const rq: GetParameterRequest = {
            Name: key,
            WithDecryption: true
        }
        return new Promise<string | undefined>(((resolve, reject) => {
            ssm.getParameter(rq, (err, data) => {
                if (err) {
                    resolve(undefined)
                } else {
                    resolve(data.Parameter?.Value)
                }
            })
        }))
    }

    const saveValue = (key: string, value: any): Promise<void> => {
        const ssm = new AWS.SSM();
        const rq: PutParameterRequest = {
            Name: key,
            Value: value,
            Type: 'SecureString',
            Overwrite: true
        }
        return new Promise<void>(((resolve, reject) => {
            ssm.putParameter(rq, (err) => {
                if (err) {
                    reject(err)
                } else {
                    resolve()
                }
            })
        }))
    }

    const clearValue = (key: string): Promise<void> => {
        const ssm = new AWS.SSM();
        const rq: DeleteParametersRequest = {
            Names: [key],
        }
        return new Promise<void>(((resolve, reject) => {
            ssm.deleteParameters(rq, (err) => {
                if (err) {
                    reject(err)
                } else {
                    resolve()
                }
            })
        }))
    }

    return {
        getString: key => getValue(key),
        saveString: async (key, value) => {
            await saveValue(key, value)
            return Promise.resolve()
        },
        getBytes: async key => {
            const bytesString = await getValue(key)
            if (bytesString) {
                return Promise.resolve(platform.base64ToBytes(bytesString))
            } else {
                return Promise.resolve(undefined)
            }
        },
        saveBytes: async (key, value) => {
            const bytesString = platform.bytesToBase64(value)
            await saveValue(key, bytesString)
            return Promise.resolve()
        },
        delete: async (key) => {
            await clearValue(key)
            return Promise.resolve()
        }
    }
}

export const awsKeyValueStorage = createAwsKeyValueStorage()


import {KeyValueStorage} from '@keeper/secrets-manager-core';
import * as AWS from "aws-sdk";
import {GetParameterRequest, PutParameterRequest, DeleteParametersRequest} from "aws-sdk/clients/ssm";

export const awsKeyValueStorage: KeyValueStorage = {

    getValue: (key: string): Promise<string | undefined> => {
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
    },

    saveValue: (key: string, value: string): Promise<void> => {
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
    },

    clearValues: (keys: string[]): Promise<void> => {
        const ssm = new AWS.SSM();
        const rq: DeleteParametersRequest = {
            Names: keys,
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
}

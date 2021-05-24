import {useEffect, useState} from 'react';
import './App.css';
import {initializeStorage, getSecrets} from '@keeper/secrets-manager-core'
import {indexedDbValueStorage} from './keyValueStorage';

const PrettyPrintJson = (data: any) =>
    <div className='secrets'><pre>{
        JSON.stringify(data, null, 2)}</pre>
    </div>


const Secrets = (props: any) => {
    const [secrets, setSecrets] = useState<any>('');
    useEffect(() => {
        const fetchSecret = async () => {
            const clientKey = window.location.pathname.slice(1)
            const storage = indexedDbValueStorage(clientKey)
            await initializeStorage(storage, clientKey, 'local.keepersecurity.com')
            try {
                const secrets = await getSecrets(storage)
                for (let record of secrets.records) {
                    record.recordKey = new Uint8Array()
                }
                setSecrets(secrets);
            }
            catch (e) {
                setSecrets(JSON.parse(e.message));
            }
        };
        fetchSecret().then();
    }, []);
    return (
        <PrettyPrintJson data={secrets}/>
    );
};

function App() {
    return (
        <div className="App">
            <Secrets/>
        </div>
    );
}

export default App;

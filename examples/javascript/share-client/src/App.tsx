import {useEffect, useState} from 'react';
import './App.css';
import {getClientId, initializeStorage, getSecrets, localConfigStorage} from '@keeper-security/secrets-manager-core'

const PrettyPrintJson = (data: any) =>
    <div className='secrets'><pre>{
        JSON.stringify(data, null, 2)}</pre>
    </div>


const Secrets = (props: any) => {
    const [secrets, setSecrets] = useState<any>('');
    useEffect(() => {
        const fetchSecret = async () => {
            const clientKey = window.location.hash.slice(1)
            const clientId = await getClientId(clientKey)
            // @ts-ignore
            const storage = localConfigStorage(clientId, true)
            await initializeStorage(storage, clientKey, 'keepersecurity.com')
            try {
                const secrets = await getSecrets({
                    storage: storage
                })
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

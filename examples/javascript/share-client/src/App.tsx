import {useEffect, useState} from 'react';
import './App.css';
import {initializeStorage, getSecrets} from '@keeper/secrets-manager-core'
import {indexedDbValueStorage} from './keyValueStorage';

const clientKey = 'SQw45mt-2OmGtQXi6EO-d2_0bZ0dLOIulrOfYeEF-bY'

const Secrets = (props: any) => {
    const [secrets, setSecrets] = useState('');
    useEffect(() => {
        const fetchSecret = async () => {
            await initializeStorage(indexedDbValueStorage, clientKey, 'local.keepersecurity.com')
            const secrets = await getSecrets(indexedDbValueStorage)
            console.log(secrets)
            setSecrets(JSON.stringify(secrets));
        };
        fetchSecret().then();
    }, []);

    return (
        <div>
            <p>{secrets}</p>
        </div>
    );
};

function App() {
    return (
        <div className="App">
            <header className="App-header">
                <Secrets/>
            </header>
        </div>
    );
}

export default App;

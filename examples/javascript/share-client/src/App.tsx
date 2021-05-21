import React, {useEffect, useState} from 'react';
import './App.css';
import {getSecrets, KeyValueStorage} from '@keeper/secrets-manager-core'

const Secrets = (props: any) => {
    const db = indexedDB.open('secrets', 1)
    if (db != null) {
        // @ts-ignore
        const transaction = db.transaction(['secrets'], 'readwrite');
        const objectStore = transaction.objectStore('secrets')
        objectStore.add()
    }
    const [secrets, setSecrets] = React.useState("");
    React.useEffect(() => {
        const fetchUser = async () => {
            const response = await fetch("https://jsonplaceholder.typicode.com/todos/1");
            const { title } = await response.json();
            setSecrets(title);
        };
        fetchUser().then();
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

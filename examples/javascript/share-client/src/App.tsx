import React from 'react';
import './App.css';
// @ts-ignore
import { hello } from 'keeper-secrets-manager'

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <p>
          {hello()}
        </p>
      </header>
    </div>
  );
}

export default App;

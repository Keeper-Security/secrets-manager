#!/usr/bin/env sh

cd ksm-azure-devops-secrets-task || exit
npm run build

cd ..
tfx extension create --manifest-globs vss-extension.json

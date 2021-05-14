


cd ..

virtualenv -p python3 venv
source venv/bin/activate

pip install -r requirements.txt


pip install -e .
rm -rf dist
sudo pip install twine
python3 setup.py sdist bdist_wheel


twine upload dist/*


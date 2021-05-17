
cd ../core

virtualenv -p python3 venv
source venv/bin/activate

pip install -r requirements.txt

echo "---------------------------"
echo "ENTER LOCAL USER PASSWORD"
echo "---------------------------"

pip install -e .
rm -rf dist *config*.json
sudo pip install twine
python3 setup.py sdist bdist_wheel

twine check dist/*

# Configuration for PyPi API Tokne is located in ~/.pypirc
twine upload -r pypi dist/*


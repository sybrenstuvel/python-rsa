#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 new-version" >&2
    exit 1
fi

DATE=$(date +'%Y-%m-%d')

sed "s/__date__\s=\s\"[^\"]*\"/__date__ = \"$DATE\"/" -i rsa/__init__.py
sed "s/__version__\s=\s\"[^\"]*\"/__version__ = \"$1\"/" -i rsa/__init__.py
poetry version "$1"

git diff
echo
echo "Don't forget to commit and tag:"
echo git commit -m \'Bumped version to $1\' rsa/__init__.py pyproject.toml
echo git tag -a version-$1 -m \'Tagged version $1\'

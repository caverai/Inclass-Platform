#!/bin/bash

mkdir -p docs

echo -e "\033[0;36mDeploying documentation assets...\033[0m"
cp -r doxygen/* docs/

if [ ! -d "docs/doxygen-awesome-css" ]; then
    echo -e "\033[0;33mDoxygen Awesome CSS missing. Downloading...\033[0m"
    git clone https://github.com/jothepro/doxygen-awesome-css.git docs/doxygen-awesome-css
fi

echo -e "\033[0;36mCleaning old documentation...\033[0m"
rm -rf docs/gen
mkdir -p docs/gen

echo -e "\033[0;32mRunning Doxygen...\033[0m"
doxygen Doxyfile

echo -e "\033[0;32mDocumentation generated at: docs/gen/html/index.html\033[0m"

if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    start docs/gen/html/index.html
elif [[ "$OSTYPE" == "darwin"* ]]; then
    open docs/gen/html/index.html
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open docs/gen/html/index.html
fi

FROM node:10

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies and TypeScript globally
RUN npm install && npm install -g typescript mocha dotenv core-js

# Copy the entire project
COPY . .

# Set the entry point to the run-tests.sh script in the tests directory
ENTRYPOINT ["./tests/run-tests.sh"]
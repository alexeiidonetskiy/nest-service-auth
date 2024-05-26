# File structure
- common/ - common submodule (submodule), which is available in all repositories. All changes
  must be poured into the repository separately from the main code.
- docs/ - documentation
- src/ - the main code of the service

##### We adhere to the following module structure:
- module-name/ - create a folder with the name of the module
    - controllers - controllers for receiving and returning the result
    - dto - data transfer objects, objects for input data validation
    - entities - postgresql objects for working with repositories and databases
    - gateways - for working with WebSockets
    - services - services with business logic
    - module-name.module.ts - a file describing the module

## Running the app

```bash
# development
$ npm run start

# watch mode
$ npm run start:dev

# production mode
$ npm run start:prod
```

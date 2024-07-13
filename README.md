# caddy-json-types

TypeScript typings for Caddy JSON configuration. This package provides comprehensive TypeScript definitions for Caddy's JSON configuration format, enabling type safety and enhanced developer experience when working with Caddy's configuration files in TypeScript projects.

## Features

- **Type Safety:** Ensure your Caddy JSON configurations are type-checked for errors.
- **Enhanced Developer Experience:** Get autocompletion and inline documentation in your editor.
- **Comprehensive Documentation:** Includes full original documentation as comments for each type and field.


## Installation

You can install the package via npm:

```bash
npm install caddy-json-types
```

Or with yarn:

```bash
yarn add caddy-json-types
```

## Usage

To use the typings in your TypeScript project, import the package in your TypeScript files:

```typescript
import type { CaddyConfig } from 'caddy-json-types';

// Example usage
const config: CaddyConfig = {
    // your Caddy JSON configuration here
};
```

## Example

Here's an example of how you can use the typings with a Caddy JSON configuration:

```typescript
import type { CaddyConfig } from 'caddy-json-types';

const config: CaddyConfig = {
    apps: {
        http: {
            servers: {
                myserver: {
                    listen: [\":443\"],
                    routes: [
                        {
                            match: [
                                {
                                    host: [\"example.com\"]
                                }
                            ],
                            handle: [
                                {
                                    handler: \"static_response\",
                                    body: \"Hello, world!\"
                                }
                            ]
                        }
                    ]
                }
            }
        }
    }
};

// Use the config object as needed
console.log(config);
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request if you have any improvements or fixes.

1. Fork the repository
2. Create a new branch (`git checkout -b my-feature-branch`)
3. Make your changes
4. Commit your changes (`git commit -am 'Add new feature'`)
5. Push to the branch (`git push origin my-feature-branch`)
6. Create a new Pull Request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

This project is not affiliated with or endorsed by the Caddy project. It is an independent project created to improve the developer experience when working with Caddy JSON configurations in TypeScript.

---

For more information on Caddy and its configuration options, please visit the official [Caddy documentation](https://caddyserver.com/docs/).


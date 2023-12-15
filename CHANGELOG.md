# Change Log
## Unreleased

## 0.4.63
### Breaking
- Use deps.edn instead of Leiningen.

## 0.3.0
### ADDED
- Async HTTP support with 3-arity handlers (#6 Thanks Snurppa)

## 0.2.1
### ADDED
- SecureRandom algorithm for MS-Windows (#5 Thanks @ikappaki)

## 0.2.0
### BREAKING CHANGES
- The default value of `use-nonce` option is changed to `false` (d76f48f)

### ADDED
- `ring-middleware-csp.core/parse` function (b9154be & #3)
- Allow boolean for directive (#2)

## 0.1.1
### CHANGES
- Use memoize for generate policy string

## 0.1.0
Initial Release

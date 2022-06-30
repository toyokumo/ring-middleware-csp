# ring-middleware-csp
Ring middleware for Content Security Policy

[![CircleCI](https://circleci.com/gh/toyokumo/ring-middleware-csp.svg?style=shield&circle-token=445e8d5d3a86d16e9daf345e032a8f9b10cdb084)](https://app.circleci.com/pipelines/github/toyokumo/ring-middleware-csp)
[![cljdoc badge](https://cljdoc.org/badge/toyokumo/ring-middleware-csp)](https://cljdoc.org/d/toyokumo/ring-middleware-csp/CURRENT)
[![Clojars Project](https://img.shields.io/clojars/v/toyokumo/ring-middleware-csp.svg)](https://clojars.org/toyokumo/ring-middleware-csp)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Installation
To install, add the following to your project `:dependencies`:

[![Clojars Project](https://clojars.org/toyokumo/ring-middleware-csp/latest-version.svg)](https://clojars.org/toyokumo/ring-middleware-csp)

## Usage

```clojure
(require '[ring-middleware-csp.core :refer [wrap-csp]]
         '[ring.util.response :refer [response]])

(defn handler [request]
  (response {:foo "bar"}))

(def policy {:default-src :none
             :script-src [:self :nonce]
             :style-src ["https://example.com" :unsafe-inline]
             :block-all-mixed-content true
             :report-uri "/csp-report"})

(def app
  (-> handler
      (wrap-csp {:policy policy})
      (other-middleware)))
```
Then, Content-Security-Policy header is added to http response.

Handlers created by `wrap-csp` support 3-arity versions for asynchronous use.

### Use nonce
You can use nonce by setting `use-nonce?` option to `true`. 
`wrap-csp` middleware inject `:csp-nonce` to request map.
You can use nonce like following.
```clojure
(defn handler [{:keys [csp-nonce] :as req}]
  {:status 200
   :headers {}
   :body (str "<script nonce=\"" csp-nonce "\">alert('foo');</script>")})
```

### Get header value from policy map
You can use `compose` function.
```clojure
(ring-middleware-csp.core/compose {:default-src :none
                                   :style-src ["https://example.com" :unsafe-inline]
                                   :block-all-mixed-content true
                                   :report-uri "/csp-report"})
=> "default-src 'none';style-src https://example.com 'unsafe-inline';block-all-mixed-content;report-uri /csp-report"

; with nonce
(ring-middleware-csp.core/compose {:default-src :none
                                   :style-src [:nonce :unsafe-inline]}
                                  "abcdefg")

=> "default-src 'none';style-src 'nonce-abcdefg' 'unsafe-inline'"
```

## Options
### `:policy`
Specify Content-Security-Policy value.
The key of map is the directive name, the value of map is the directive value.
Values are keyword, string or collection of them.

e.g.
```clojure
{:policy {:default-src :none
          :script-src [:self :nonce]
          :style-src ["https://example.com" :unsafe-inline]
          :report-uri "/csp-report"}}
```

### `:report-only?`
If `:report-only?` is set to true, use "Content-Security-Policy-Report-Only" as header name.

### `:policy-generator`
By setting a function in `:policy-generator`, you can set a dynamic policy according to the request.
The argument of the function is ring request map, the return value of it is policy map (same style as `:policy`).
If the function returns `nil`, use default policy.

### `:report-handler` and `:report-uri`
By using `:report-handler`, you can handle report request.
`:report-uri` is the path to use report-handler.
`:report-handler` is ring-style report handler (you must return valid response map).
If use `:report-handler` or `:report-uri`, must set both `:report-handler` and `:report-uri`.

WARN: `:report-uri` option and `:report-uri` directive in `:policy` is independent config.
Even if you set `:report-uri` option, the report-uri directive is NOT added automatically.

e.g.
```clojure
{:policy {:default-src :self
          :report-uri "/csp-report"}
 :report-uri "/csp-report"
 :report-handler (fn [req]
                   (response {:foo "bar"}))}
```

### `:use-nonce?`
The default value is `false`.
If you set to `true`, enable to generate nonce.

### `:nonce-generator`
By using `:nonce-generator`, you can use custom nonce generator.
Default generator use [`SecureRandom`](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html) (using "NativePRNGNonBlocking" algorithm
or, on MS-Windows, the [default implementation](https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SecureRandomImp)) and
[`java.util.Base64`](https://docs.oracle.com/javase/8/docs/api/java/util/Base64.html).
It generates base64 string from 256bit random data.

e.g.
```clojure
{:policy {:default-src :self
          :script-src [:self :nonce]}
 :nonce-generator (fn []
                    "STATIC-NONCE")} ; DON'T use static nonce for security reason
```

## Testing
```
lein test
```

## Formatting
Use [cljstyle](https://github.com/greglook/cljstyle).
```
cljstyle fix
```

## License

Copyright 2020 Toyokumo,Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

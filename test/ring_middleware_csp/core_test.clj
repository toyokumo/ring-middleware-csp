(ns ring-middleware-csp.core-test
  (:require
   [clojure.test :refer :all]
   [ring-middleware-csp.core :refer :all]))

(deftest compose-test
  (is (= "" (compose {})))
  (is (= "default-src 'self'" (compose {:default-src :self})))
  (is (= "default-src 'self'" (compose {:default-src [:self]})))
  (is (= "default-src 'self' https://example.com;connect-src 'none';script-src 'self' https://script.example.com;style-src 'unsafe-inline' https://style.example.com"
         (compose {:default-src [:self "https://example.com"]
                   :connect-src :none
                   :script-src [:self "https://script.example.com"]
                   :style-src [:unsafe-inline "https://style.example.com"]}))))

(deftest wrap-csp-test
  (let [handler (constantly {:status 200 :headers {} :body ""})]
    (is (= "default-src 'self'"
           (get-in ((wrap-csp handler {:policy {:default-src :self}}) {})
                   [:headers "Content-Security-Policy"])))
    (is (= "default-src 'self'"
           (get-in ((wrap-csp handler {:policy {:default-src :self}
                                       :report-only? true}) {})
                   [:headers "Content-Security-Policy-Report-Only"])))))

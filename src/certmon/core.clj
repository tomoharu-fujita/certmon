(ns certmon.core
  (:import [javax.net.ssl HttpsURLConnection SSLSocket SSLSocketFactory SSLSession]
          [java.security.cert X509Certificate]
          [javax.security.auth.x500 X500Principal]))


(defn- format-certs [^X509Certificate cert]
  (assoc {}
    :subject (.. cert getSubjectX500Principal toString)
    :issure  (.. cert getIssuerX500Principal toString)
    :expire  (.. cert getNotAfter toString)
    :since   (.. cert getNotBefore toString)))

(defn
  ^{:doc "get server cert information from a specified host"}
  get-cert [^String hostname ^long port]
  (with-open [^SSLSocket socket (doto
                                  (. (HttpsURLConnection/getDefaultSSLSocketFactory)
                                   createSocket
                                   hostname port) (.startHandshake))]
   (mapv format-certs (.. socket (getSession) (getPeerCertificates)))
  ))

{
  "subject": {
    "commonName": {{ toJson .Subject.CommonName }}
  },
  "sans": {{ toJson .SANs }},
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["clientAuth"]
}

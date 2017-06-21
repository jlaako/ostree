/* vi: set et sw=2 ts=2 cino=t0,(0: */
/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */

#include <stdio.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs7.h>
#include <gnutls/crypto.h>

int main (int argc, char *argv[])
{
  if (argc < 3)
    return -1;

  int ec;
  gnutls_datum_t cert_data = { NULL, 0 };
  gnutls_datum_t priv_data = { NULL, 0 };
  gnutls_x509_crt_t cert;
  gnutls_privkey_t privkey;
  //gnutls_x509_privkey_t privkey;

  if (ec = gnutls_x509_crt_init (&cert))
  {
    printf("gnutls_x509_crt_init(): %s\n", gnutls_strerror(ec));
    return -1;
  }
  if (ec = gnutls_load_file (argv[1], &cert_data))
  {
    printf("gnutls_load_file(\"%s\"): %s\n", argv[1], gnutls_strerror(ec));
    return -1;
  }
  if (ec = gnutls_x509_crt_import (cert, &cert_data, GNUTLS_X509_FMT_PEM))
  {
    printf("gnutls_crt_import(): %s\n", gnutls_strerror(ec));
    return -1;
  }
  gnutls_free (cert_data.data);
  if (ec = gnutls_privkey_init (&privkey))
  {
    printf("gnutls_privkey_init(): %s\n", gnutls_strerror(ec));
    return -1;
  }
  /*if (ec = gnutls_x509_privkey_init (&privkey))
  {
    printf("gnutls_x509_privkey_init(): %s\n", gnutls_strerror(ec));
    return -1;
  }*/
  if (ec = gnutls_load_file (argv[2], &priv_data))
  {
    printf("gnutls_load_file(\"%s\"): %s\n", argv[2], gnutls_strerror(ec));
    return -1;
  }
  if (ec = gnutls_privkey_import_x509_raw (privkey, &priv_data, GNUTLS_X509_FMT_PEM, NULL, GNUTLS_PKCS_PLAIN|GNUTLS_PKCS_NULL_PASSWORD))
  {
    printf("gnutls_privkey_import_x509_raw(): %s\n", gnutls_strerror(ec));
    return -1;
  }
  /*if (ec = gnutls_x509_privkey_import2 (privkey, &priv_data, GNUTLS_X509_FMT_PEM, NULL, GNUTLS_PKCS_PLAIN|GNUTLS_PKCS_NULL_PASSWORD))
  {
    printf("gnutls_x509_privkey_import2(): %s\n", gnutls_strerror(ec));
    return -1;
  }
  if (ec = gnutls_x509_crt_set_key (cert, privkey))
  {
    printf("gnutls_x509_set_key(): %s\n", gnutls_strerror(ec));
    return -1;
  }*/
  gnutls_free (priv_data.data);


  gnutls_pkcs7_t pkcs7;
  const char *testdata = "Hello world!";
  gnutls_datum_t testdatum;
  gnutls_datum_t outdata = { NULL, 0 };

  testdatum.data = testdata;
  testdatum.size = strlen(testdata);
  if (ec = gnutls_pkcs7_init (&pkcs7))
  {
    printf("gnutls_pkcs7_init(): %s\n", gnutls_strerror(ec));
    return -1;
  }
  if (ec = gnutls_pkcs7_sign (pkcs7, cert, privkey, &testdatum, NULL, NULL, GNUTLS_DIG_SHA256, GNUTLS_PKCS7_INCLUDE_TIME))
  {
    printf("gnutls_pkcs7_sign(): %s\n", gnutls_strerror(ec));
    return -1;
  }
  if (ec = gnutls_pkcs7_print (pkcs7, GNUTLS_CRT_PRINT_COMPACT, &outdata))
  {
    printf("gnutls_pkcs7_print(): %s\n", gnutls_strerror(ec));
    return -1;
  }
  puts(outdata.data);
  gnutls_free (outdata.data);
  if (ec = gnutls_pkcs7_export2 (pkcs7, GNUTLS_X509_FMT_PEM, &outdata))
  {
    printf("gnutls_pkcs7_export2(): %s\n", gnutls_strerror(ec));
    return -1;
  }
  puts(outdata.data);
  //gnutls_free (outdata.data);
  gnutls_pkcs7_deinit (pkcs7);

  if (ec = gnutls_pkcs7_init (&pkcs7))
  {
    printf("gnutls_pkcs7_init(): %s\n", gnutls_strerror(ec));
    return -1;
  }
  if (ec = gnutls_pkcs7_import (pkcs7, &outdata, GNUTLS_X509_FMT_PEM))
  {
    printf("gnutls_pkcs7_import(): %s\n", gnutls_strerror(ec));
    return -1;
  }
  if (ec = gnutls_pkcs7_verify_direct (pkcs7, cert, 0, &testdatum, 0))
  {
    printf("gnutls_pkcs7_verify_direct(): %s\n", gnutls_strerror(ec));
    return -1;
  }
  gnutls_free (outdata.data);
  gnutls_pkcs7_deinit (pkcs7);
  printf("verify result: %d\n", ec);


  gnutls_privkey_deinit (privkey);
  //gnutls_x509_privkey_deinit (privkey);
  gnutls_x509_crt_deinit (cert);

  return 0;
}


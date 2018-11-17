package com.metamx.tranquility.security

import java.io.FileInputStream
import java.io.IOException
import java.security.{NoSuchAlgorithmException, KeyStoreException, KeyManagementException, KeyStore}
import java.security.cert.CertificateException
import javax.net.ssl.{TrustManagerFactory, SSLContext}

import com.metamx.common.scala.Logging
import com.metamx.tranquility.config.PropertiesBasedConfig

object SSLContextMaker extends Logging
{
  def createSSLContextOption(
    config: PropertiesBasedConfig
  ): Option[SSLContext] =
  {
    createSSLContextOption(
      Some(config.tlsEnable),
      Some(config.tlsProtocol),
      Some(config.tlsTrustStoreType),
      Some(config.tlsTrustStorePath),
      Some(config.tlsTrustStoreAlgorithm),
      Some(config.tlsTrustStorePassword)
    )
  }

  def createSSLContextOption(
    tlsEnable: Option[Boolean] = None,
    tlsProtocol: Option[String] = None,
    tlsTrustStoreType: Option[String] = None,
    tlsTrustStorePath: Option[String] = None,
    tlsTrustStoreAlgorithm: Option[String] = None,
    tlsTrustStorePassword: Option[String] = None
  ): Option[SSLContext] =
  {
    if (!tlsEnable.isDefined || !tlsEnable.get) {
      log.info("TLS is not enabled, skipping SSLContext creation.")
      None
    } else {
      log.info("TLS is enabled, creating SSLContext.")

      var sslContext: SSLContext = null
      try {
        sslContext = SSLContext.getInstance(tlsProtocol.getOrElse("TLSv1.2"))
        var keyStore = KeyStore.getInstance(tlsTrustStoreType.getOrElse(KeyStore.getDefaultType()))
        keyStore.load(
          new FileInputStream(tlsTrustStorePath.getOrElse("")),
          tlsTrustStorePassword.getOrElse("").toCharArray
        )
        var trustManagerFactory = TrustManagerFactory.getInstance(
          tlsTrustStoreAlgorithm.getOrElse(TrustManagerFactory.getDefaultAlgorithm())
        )
        trustManagerFactory.init(keyStore)
        sslContext.init(null, trustManagerFactory.getTrustManagers, null)
      }
      catch {
        case ex@(_: CertificateException |
                 _: KeyManagementException |
                 _: IOException |
                 _: KeyStoreException |
                 _: NoSuchAlgorithmException) =>
          throw new RuntimeException(ex)
      }

      Some(sslContext)
    }
  }
}

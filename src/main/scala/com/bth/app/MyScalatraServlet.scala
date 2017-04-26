package com.bth.app

import java.net.{HttpURLConnection, URL, URLEncoder}
import java.security.MessageDigest
import java.util.Base64

import com.bth.util.Encryption
import play.api.libs.json._

import scala.util.Random

class MyScalatraServlet extends ScalatraoauthclientStack {

  private val cookieKey: String = "userCookie"
  private val encryptionKey: String = "My Secret Key"

  // The OAuth Server (no ending slash here)
  private val OAUTH_SERVER = "https://localhost:8443"
  private val CALLBACK_URL = "https://localhost:8444/OAuth2Callback"
  private val CLIENT_URL = "https://localhost:8444"

  private val scope: Seq[String] = Seq("openid", "email", "profile")

  /**
    * Return true if a cookie session exists
    * @return True of false
    */
  def hasCookie: Boolean = {
    cookies.get(cookieKey) match {
      case Some(_) => true
      case None => false
    }
  }

  /**
    * Encrypt a string
    * @param string The string to be encrypted
    * @return Encrypted string
    */
  def encrypt(string: String): String = Encryption.encrypt(this.encryptionKey, string)

  /**
    * Decrypt a string
    * @param encrypted  The encrypted string to be decrypted
    * @return Decrypted string
    */
  def decrypt(encrypted: String): String = Encryption.decrypt(this.encryptionKey, encrypted)

  /**
    * Sets the cookie
    * @param value  The value for the cookie
    */
  def setCookie(value: String): Unit = cookies.set(this.cookieKey, this.encrypt(value))

  /**
    * Check if user is authenticated
    * @return True if the user is authed, else False
    */
  def isAuthenticated: Boolean = this.hasCookie

  /**
    * Return the user info requested
    * @return Map containing the user info that was claimed from the authorization server
    */
  def getUserInfo: Option[Map[String, Option[String]]] = {
    cookies.get(this.cookieKey) match {
      case Some(cookie) =>
        // Decrypt the cookie value
        val decrypted = this.decrypt(cookie)

        // Parse the decrypted cookie value as Json and
        // map the values as Option[String]
        val json: Map[String, Option[String]] = Json.parse(decrypted).as[Map[String, JsValue]] map {
          case (key, value) => (key, value.asOpt[String])
        }

        Some(json)
      case None => None
    }
  }

  def scopeAsString(scope: Seq[String]): String = scope.mkString("%20")

  get("/profile") {
    if (this.isAuthenticated) {
      contentType="text/html"
      layoutTemplate("/profile.jade",
        "title" -> "Client",
        "username" -> this.getUserInfo.get("nickname").get,
        "isAuthenticated" -> this.isAuthenticated,
        "user" -> cookies.get("debugId").getOrElse("{}")
      )
    }
    else {
      redirect("/")
    }
  }

  get("/logout") {
    cookies.delete(this.cookieKey)
    redirect(this.OAUTH_SERVER + "/logout?redirect=" + this.CLIENT_URL)
  }

  get("/") {
    // Redirect the user to the login page if not logged in
    if (!this.isAuthenticated) {
      contentType="text/html"
      layoutTemplate("/login.jade", "title" -> "Client", "scope" -> this.scope)
    }
    else {
      contentType="text/html"
      layoutTemplate("/home.jade",
        "title" -> "Client",
        "username" -> this.getUserInfo.get("nickname").get,
        "isAuthenticated" -> this.isAuthenticated,
        "user" -> cookies.get("debugId").getOrElse("{}")
      )
    }
  }

  get("/start") {
    val outhProvider: String = this.OAUTH_SERVER + "/authorize"

    val callbackUrl: String = this.CALLBACK_URL
    val encodedCBUrl: String = URLEncoder.encode(callbackUrl,"UTF-8")

    val clientID: String = "t83g-aaa"

    val rnd = scala.collection.mutable.ArrayBuffer.fill[Byte](10)(0).toArray
    Random.nextBytes(rnd)
    val md = MessageDigest.getInstance("SHA-256")
    md.update(rnd)
    val state = Base64.getEncoder.withoutPadding.encodeToString(md.digest)
    request.getSession.setAttribute("oauthstate",state)

    val scopeString = this.scopeAsString(this.scope)

    val oURL = s"""$outhProvider?scope=$scopeString&state=$state&redirect_uri=$encodedCBUrl&response_type=code&client_id=$clientID"""
    response.sendRedirect(oURL)
  }

  get("/OAuth2Callback") {

    val accessTokenURL = this.OAUTH_SERVER + "/token"
    val callbackUrl = this.CALLBACK_URL
    val clientID = "t83g-aaa" //provide your own
    val clientSecret = "Nxfq-rj7Y-HgtH" //provide your own

    val out = response.getWriter

    //Extract params out of the query url
    val qs = request.getQueryString.split("&").map(_.split("=")).map(a=> (a(0) -> a(1))).toMap
    out.println(qs)
    //TODO validate that we have a success
    val stateIn = qs("state")
    val code = qs("code")

    //TODO: validate state as [N]OK
    val stateStored = request.getSession.getAttribute("oauthstate")
    out.println(s"storedState: $stateStored")
    out.println(s"inState: $stateIn")
    out.println(stateStored == stateIn)

    //Exchange code for access token and ID token
    val body = s"code=$code&client_id=$clientID&client_secret=$clientSecret&redirect_uri=$callbackUrl&grant_type=authorization_code"
    val con = new URL(accessTokenURL).openConnection().asInstanceOf[HttpURLConnection]
    con.setDoOutput(true)
    con.setRequestMethod("POST")
    con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
    con.getOutputStream.write(body.getBytes("UTF-8"))
    val res = scala.io.Source.fromInputStream(con.getInputStream).mkString
    out.println("=============")
    out.println(res)
    out.println("=============")

    // Parse out the access token from the response
    val js = Json.parse(res)
    val accessToken = (js \ "access_token").as[String]
    val tokenType = (js \ "token_type").as[String]
    val expiresIn = (js \ "expires_in").as[Int]
    val idToken = (js \ "id_token").as[String]
    out.println(accessToken)
    out.println(tokenType)
    out.println(expiresIn)
    out.println(idToken)

    //Digest the "id token", will contain basic profile of the user
    val idt = idToken.split("""\.""")
    val id = Json.parse(java.util.Base64.getDecoder.decode(idt(1)))
    out.println("=============")
    out.println(Json.prettyPrint(id))
    cookies.set("debugId", Json.stringify(id))
    out.println("=============")

    val test = Json.stringify(id)
    out.println("=============COOKIE TO SET")
    val userInfo = (id \ "user_info").get
    val jsonString = Json.stringify(Json.toJson(userInfo))
    this.setCookie(jsonString)
    out.println("=============")
    redirect("/")
  }

}

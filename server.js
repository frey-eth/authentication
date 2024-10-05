import http from "http";
import next from "next";
import express from "express";
import bodyParser from "body-parser";
import session from "express-session";
import cookieParser from "cookie-parser";
import cors from "cors";
import errorHandler from "errorhandler";

import { Fido2Lib } from "fido2-lib";
import crypto from "crypto";
import base64url from "base64url";

const dev = process.env.NODE_ENV !== "production";
const nextApp = next({ dev });
const handle = nextApp.getRequestHandler();

const fido = new Fido2Lib({
  timeout: 60000,
  rpId: "localhost",
  rpName: "What PWA Can Do Today",
  rpIcon: "https://whatpwacando.today/src/img/icons/icon-512x512.png",
  challengeSize: 128,
  attestation: "none",
  cryptoParams: [-7, -257],
  authenticatorAttachment: "platform",
  authenticatorRequireResidentKey: false,
  authenticatorUserVerification: "required",
  authenticatorSelection: {
    authenticatorAttachment: "platform", // 'platform' for device authenticators (like fingerprint)
    userVerification: "preferred", // Use 'required' if you want to enforce
  },
});

const origin = "http://localhost:3000"; // Changed to match Next.js default port and protocol

nextApp.prepare().then(() => {
  const app = express();

  app.use(cookieParser("whatpwacandotoday"));
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(bodyParser.json({ limit: "5mb" }));
  app.use(
    cors({
      origin,
      credentials: true,
    })
  );

  app.use(
    session({
      secret: "whatpwacandotoday",
      resave: true,
      saveUninitialized: true,
      cookie: {
        secure: false,
        maxAge: 60000,
      },
    })
  );

  app.use(errorHandler());

  // WebAuthn routes
  app.get("/registration-options", async (req, res) => {
    const registrationOptions = await fido.attestationOptions();

    req.session.challenge = Buffer.from(registrationOptions.challenge);
    req.session.userHandle = crypto.randomBytes(32);

    registrationOptions.user.id = req.session.userHandle;
    registrationOptions.challenge = Buffer.from(registrationOptions.challenge);

    // iOS
    registrationOptions.authenticatorSelection = {
      authenticatorAttachment: "platform",
    };

    res.json(registrationOptions);
  });

  app.post("/register", async (req, res) => {
    const { credential } = req.body;

    const challenge = new Uint8Array(req.session.challenge.data).buffer;
    credential.rawId = new Uint8Array(
      Buffer.from(credential.rawId, "base64")
    ).buffer;
    credential.response.attestationObject = base64url.decode(
      credential.response.attestationObject,
      "base64"
    );
    credential.response.clientDataJSON = base64url.decode(
      credential.response.clientDataJSON,
      "base64"
    );

    const attestationExpectations = {
      challenge,
      origin,
      factor: "either",
    };

    try {
      const regResult = await fido.attestationResult(
        credential,
        attestationExpectations
      );

      req.session.publicKey = regResult.authnrData.get(
        "credentialPublicKeyPem"
      );
      req.session.prevCounter = regResult.authnrData.get("counter");

      res.json({ status: "ok" });
    } catch (e) {
      console.log("error", e);
      res.status(500).json({ status: "failed" });
    }
  });

  app.get("/authentication-options", async (req, res) => {
    const authnOptions = await fido.assertionOptions();

    req.session.challenge = Buffer.from(authnOptions.challenge);

    authnOptions.challenge = Buffer.from(authnOptions.challenge);

    res.json(authnOptions);
  });

  app.post("/authenticate", async (req, res) => {
    const { credential } = req.body;

    credential.rawId = new Uint8Array(
      Buffer.from(credential.rawId, "base64")
    ).buffer;

    const challenge = new Uint8Array(req.session.challenge.data).buffer;
    const { publicKey, prevCounter } = req.session;

    if (publicKey === "undefined" || prevCounter === undefined) {
      res.status(404).json({ status: "not found" });
    } else {
      const assertionExpectations = {
        challenge,
        origin,
        factor: "either",
        publicKey,
        prevCounter,
        userHandle: new Uint8Array(
          Buffer.from(req.session.userHandle, "base64")
        ).buffer, //new Uint8Array(Buffer.from(req.session.userHandle.data)).buffer
      };

      try {
        await fido.assertionResult(credential, assertionExpectations); // will throw on error

        res.json({ status: "ok" });
      } catch (e) {
        console.log("error", e);
        res.status(500).json({ status: "failed" });
      }
    }
  });

  // Handle all other routes with Next.js
  app.all("*", (req, res) => {
    return handle(req, res);
  });

  const server = http.createServer(app);

  server.listen(3000, (err) => {
    if (err) throw err;
    console.log("> Ready on http://localhost:3000");
  });
});

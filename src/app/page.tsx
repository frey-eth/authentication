"use client";
import Image from "next/image";
import auth_logo from "../../public/icons/auth.svg";
import { useState } from "react";

const bufferToBase64 = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  const binary = bytes.reduce((acc, byte) => acc + String.fromCharCode(byte), '');
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};

const base64ToBuffer = (base64: string | ArrayBuffer): Uint8Array => {
  // If base64 is already an ArrayBuffer, return it as Uint8Array
  if (base64 instanceof ArrayBuffer) {
    return new Uint8Array(base64);
  }

  // Ensure base64 is a string
  const base64String = typeof base64 === 'string' ? base64 : String(base64);

  // Remove any non-base64 characters (including whitespace)
  const cleanedBase64 = base64String.replace(/[^A-Za-z0-9+/=_-]/g, '');

  // Replace URL-safe characters
  const base64Fixed = cleanedBase64.replace(/-/g, "+").replace(/_/g, "/");

  // Add padding if necessary
  const padding = "=".repeat((4 - (base64Fixed.length % 4)) % 4);
  const base64Final = base64Fixed + padding;

  try {
    return Uint8Array.from(atob(base64Final), (c) => c.charCodeAt(0));
  } catch (error) {
    console.error('Failed to decode base64 string:', base64Final, error);
    return new Uint8Array(0); // Return empty array on error
  }
};

export default function Home() {
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState("");

  // Function to handle authentication
  async function authenticate() {
    setIsLoading(true);
    try {
      // Fetch authentication options from the server
      const response = await fetch(
        "http://localhost:3000/authentication-options",
        {
          method: "GET",
          credentials: "include",
        }
      );

      const credentialRequestOptions = await response.json();

      // Convert the challenge to Uint8Array
      credentialRequestOptions.challenge = base64ToBuffer(
        credentialRequestOptions.challenge
      );

      // Check if allowCredentials is defined and is an array
      if (Array.isArray(credentialRequestOptions.allowCredentials)) {
        credentialRequestOptions.allowCredentials =
          credentialRequestOptions.allowCredentials.map((cred: any) => ({
            ...cred,
            id: base64ToBuffer(cred.id),
          }));
      } else {
        console.warn("allowCredentials is not defined or not an array");
        credentialRequestOptions.allowCredentials = [];
      }

      // Call WebAuthn API to get credentials
      const credential = (await navigator.credentials.get({
        publicKey: credentialRequestOptions,
      })) as PublicKeyCredential;

      // Prepare data to send to the server for verification
      const data = {
        rawId: bufferToBase64(credential.rawId),
        response: {
          authenticatorData: bufferToBase64(
            (credential.response as AuthenticatorAssertionResponse)
              .authenticatorData
          ),
          clientDataJSON: bufferToBase64(credential.response.clientDataJSON),
          signature: bufferToBase64(
            (credential.response as AuthenticatorAssertionResponse).signature
          ),
          userHandle: bufferToBase64(
            (credential.response as AuthenticatorAssertionResponse)
              .userHandle || new Uint8Array()
          ),
        },
        id: credential.id,
        type: credential.type,
      };

      // Send the credentials to the server for verification
      const authResponse = await fetch("http://localhost:3000/authenticate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: data }),
        credentials: "include",
      });

      const result = await authResponse.json();

      if (result.status === "ok") {
        setMessage("Authentication successful!");
      } else {
        setMessage("Authentication failed!");
      }
    } catch (error) {
      console.error("Authentication failed", error);
      setMessage("Authentication failed!");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center h-full">
      <button
        onClick={authenticate}
        disabled={isLoading}
        className="bg-white flex flex-row items-center justify-center text-black p-4 rounded-md"
      >
        <div className="h-6 w-6 relative">
          <Image
            src={auth_logo}
            alt="auth_logo"
            fill
            style={{ objectFit: "contain" }}
          />
        </div>
        <span className="ml-2">Authenticate</span>
      </button>

      {isLoading && <p>Loading...</p>}
      {message && <p>{message}</p>}
    </div>
  );
}

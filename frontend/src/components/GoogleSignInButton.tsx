import React, { useEffect, useRef, useState } from 'react';

type GoogleSignInButtonProps = {
  onCredential: (credential: string) => Promise<void> | void;
  onError?: (message: string) => void;
};

const GOOGLE_SCRIPT_SRC = 'https://accounts.google.com/gsi/client';

const loadGoogleScript = (): Promise<void> => {
  return new Promise((resolve, reject) => {
    const existingScript = document.querySelector(
      `script[src="${GOOGLE_SCRIPT_SRC}"]`
    ) as HTMLScriptElement | null;

    if (existingScript) {
      if (window.google?.accounts?.id) {
        resolve();
        return;
      }

      existingScript.addEventListener('load', () => resolve(), { once: true });
      existingScript.addEventListener(
        'error',
        () => reject(new Error('Failed to load Google Sign-In')),
        { once: true }
      );
      return;
    }

    const script = document.createElement('script');
    script.src = GOOGLE_SCRIPT_SRC;
    script.async = true;
    script.defer = true;
    script.dataset.googleGsi = 'true';

    script.onload = () => resolve();
    script.onerror = () => reject(new Error('Failed to load Google Sign-In'));

    document.head.appendChild(script);
  });
};

const waitForGoogleIdentity = (timeoutMs = 5000): Promise<void> => {
  return new Promise((resolve, reject) => {
    if (window.google?.accounts?.id) {
      resolve();
      return;
    }

    const startedAt = Date.now();
    const intervalId = window.setInterval(() => {
      if (window.google?.accounts?.id) {
        window.clearInterval(intervalId);
        resolve();
        return;
      }

      if (Date.now() - startedAt >= timeoutMs) {
        window.clearInterval(intervalId);
        reject(new Error('Google Identity Services unavailable'));
      }
    }, 50);
  });
};

export const GoogleSignInButton: React.FC<GoogleSignInButtonProps> = ({
  onCredential,
  onError,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    let isMounted = true;
    const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined;

    if (!clientId) {
      onError?.('Missing VITE_GOOGLE_CLIENT_ID in the frontend environment.');
      return () => undefined;
    }

    loadGoogleScript()
      .then(() => waitForGoogleIdentity())
      .then(() => {
        if (!isMounted || !containerRef.current) return;

        window.google.accounts.id.initialize({
          client_id: clientId,
          callback: (response) => {
            if (!response.credential) {
              onError?.('Google Sign-In did not return a credential.');
              return;
            }
            void onCredential(response.credential);
          },
          ux_mode: 'popup',
        });

        containerRef.current.innerHTML = '';
        window.google.accounts.id.renderButton(containerRef.current, {
          theme: 'outline',
          size: 'large',
          text: 'signin_with',
          shape: 'pill',
          logo_alignment: 'left',
          width: 320,
        });

        setIsReady(true);
      })
      .catch((err) => {
        if (isMounted) {
          onError?.(err.message || 'Unable to load Google Sign-In.');
        }
      });

    return () => {
      isMounted = false;
    };
  }, [onCredential, onError]);

  return (
    <div className="flex flex-col items-center">
      <div ref={containerRef} className="flex justify-center" />
      {!isReady && (
        <p className="mt-3 text-xs text-gray-500">Loading Google Sign-In...</p>
      )}
    </div>
  );
};

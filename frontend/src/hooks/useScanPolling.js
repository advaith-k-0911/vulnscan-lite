import { useState, useEffect, useRef, useCallback } from 'react';
import { getScanStatus, getScan } from '../services/api';

/**
 * Custom React hook for polling scan execution status with network glitch resilience.
 *
 * @param {string|null} scanId - UUID of the scan to poll
 * @param {Object} options - Configuration options
 * @param {number} [options.interval=2000] - Base polling interval in ms
 * @param {number} [options.maxRetries=3] - Transient network error retries before failing
 * @param {Function} [options.onComplete] - Callback invoked upon scan completion
 * @param {Function} [options.onError] - Callback invoked upon scan failure
 * @returns {Object} { status, isPolling, scanData, error, networkWarning, resetPolling }
 */
export function useScanPolling(scanId, options = {}) {
  const { interval = 2000, maxRetries = 3, onComplete, onError } = options;

  const [status, setStatus] = useState('IDLE');
  const [isPolling, setIsPolling] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [error, setError] = useState(null);
  const [networkWarning, setNetworkWarning] = useState(null);

  const timerRef = useRef(null);
  const isMountedRef = useRef(true);
  const consecutiveErrorsRef = useRef(0);

  // Store latest callbacks in refs to prevent useEffect teardown loops
  const onCompleteRef = useRef(onComplete);
  const onErrorRef = useRef(onError);
  useEffect(() => {
    onCompleteRef.current = onComplete;
    onErrorRef.current = onError;
  });

  const clearTimer = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const resetPolling = useCallback(() => {
    clearTimer();
    consecutiveErrorsRef.current = 0;
    setStatus('IDLE');
    setIsPolling(false);
    setScanData(null);
    setError(null);
    setNetworkWarning(null);
  }, [clearTimer]);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      clearTimer();
    };
  }, [clearTimer]);

  useEffect(() => {
    if (!scanId) {
      resetPolling();
      return;
    }

    let active = true;
    setIsPolling(true);
    setStatus('QUEUED');
    setError(null);
    setNetworkWarning(null);
    consecutiveErrorsRef.current = 0;

    const poll = async () => {
      if (!active || !isMountedRef.current) return;

      try {
        const statusRes = await getScanStatus(scanId);
        const currentStatus = (statusRes.status || 'QUEUED').toUpperCase();

        if (!active || !isMountedRef.current) return;

        // Reset network warning on successful response
        consecutiveErrorsRef.current = 0;
        setNetworkWarning(null);
        setStatus(currentStatus);

        if (currentStatus === 'COMPLETED') {
          setIsPolling(false);
          try {
            const fullData = await getScan(scanId);
            if (active && isMountedRef.current) {
              setScanData(fullData);
              if (onCompleteRef.current) onCompleteRef.current(fullData);
            }
          } catch {
            if (active && isMountedRef.current) {
              const basicData = { id: scanId, status: 'COMPLETED' };
              setScanData(basicData);
              if (onCompleteRef.current) onCompleteRef.current(basicData);
            }
          }
          return;
        }

        if (currentStatus === 'FAILED') {
          setIsPolling(false);
          const fullData = await getScan(scanId).catch(() => null);
          const errMsg =
            fullData?.error?.message || 'The security assessment could not be completed.';
          if (active && isMountedRef.current) {
            setError(errMsg);
            setScanData(fullData);
            if (onErrorRef.current) onErrorRef.current(errMsg);
          }
          return;
        }

        // Schedule next poll cycle
        if (active && isMountedRef.current) {
          timerRef.current = setTimeout(poll, interval);
        }
      } catch (err) {
        if (!active || !isMountedRef.current) return;

        consecutiveErrorsRef.current += 1;
        if (consecutiveErrorsRef.current <= maxRetries) {
          // Subtle warning while retrying
          setNetworkWarning(`Reconnecting to scan status service (attempt ${consecutiveErrorsRef.current}/${maxRetries})...`);
          timerRef.current = setTimeout(poll, interval + 500);
        } else {
          setIsPolling(false);
          setNetworkWarning(null);
          const errorMsg =
            err.message || 'Unable to communicate with the scanner API. Please check your connection.';
          setError(errorMsg);
          setStatus('FAILED');
          if (onErrorRef.current) onErrorRef.current(errorMsg);
        }
      }
    };

    poll();

    return () => {
      active = false;
      clearTimer();
    };
  }, [scanId, interval, maxRetries, clearTimer, resetPolling]);

  return {
    status,
    isPolling,
    scanData,
    error,
    networkWarning,
    resetPolling,
  };
}

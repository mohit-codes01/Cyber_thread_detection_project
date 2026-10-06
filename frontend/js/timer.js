/**
 * AccurateTimer - Robust, Time-Based Engine for Continuous & Smooth Timing
 * 
 * Addresses and fixes:
 * 1. Timer freezing/skipping due to reliance on drift-prone counter increments.
 * 2. Stale closures and race conditions.
 * 3. Duplicate intervals when starting multiple times, pausing, resuming, or re-rendering.
 * 4. Proper timestamp calculation (Date.now()) ensuring precision even if the browser/app is temporarily busy.
 * 5. Pause and resume preserving elapsed time without resetting.
 * 6. Clean stopping at 00:00 on countdown mode with no negative values.
 * 7. Comprehensive cleanup on unmount/stop to prevent memory leaks and orphaned intervals.
 */

export class AccurateTimer {
  constructor(options = {}) {
    this.mode = options.mode || "countup"; // 'countup' or 'countdown'
    this.initialSeconds = options.initialSeconds || 0;
    this.onTick = options.onTick || null; // callback(formattedTime, totalSeconds)
    this.onComplete = options.onComplete || null;

    this.timerId = null;
    this.startTime = null;
    this.elapsedBeforePause = 0;
    this.isRunning = false;
    this.isPaused = false;
  }

  /**
   * Start timer. If already running, avoids creating duplicate intervals.
   */
  start() {
    if (this.isRunning && !this.isPaused) {
      return; // Prevent duplicate timers running simultaneously
    }

    this._clearInterval();

    const now = Date.now();
    this.startTime = now - this.elapsedBeforePause;
    this.isRunning = true;
    this.isPaused = false;

    // Immediately trigger tick so UI updates without 1s latency
    this._tick();

    // Single active interval loop
    this.timerId = setInterval(() => this._tick(), 1000);
  }

  /**
   * Pause timer without resetting elapsed time.
   */
  pause() {
    if (!this.isRunning || this.isPaused) return;

    this.elapsedBeforePause = Date.now() - this.startTime;
    this.isPaused = true;
    this.isRunning = false;

    this._clearInterval();
  }

  /**
   * Resume timer retaining elapsed time.
   */
  resume() {
    if (!this.isPaused) return;
    this.start();
  }

  /**
   * Stop timer and clean up interval.
   */
  stop() {
    this._clearInterval();
    this.isRunning = false;
    this.isPaused = false;
    this.startTime = null;
    this.elapsedBeforePause = 0;
  }

  /**
   * Reset timer to a new or initial value.
   */
  reset(newInitialSeconds = null) {
    this.stop();
    if (newInitialSeconds !== null) {
      this.initialSeconds = newInitialSeconds;
    }
  }

  /**
   * Get current elapsed seconds calculated directly from timestamp.
   */
  getElapsedSeconds() {
    if (!this.startTime) return Math.floor(this.elapsedBeforePause / 1000);
    const totalMs = this.isRunning
      ? Date.now() - this.startTime
      : this.elapsedBeforePause;
    return Math.floor(totalMs / 1000);
  }

  /**
   * Internal tick handler using timestamp math.
   */
  _tick() {
    if (!this.isRunning) return;

    const now = Date.now();
    const elapsedMs = Math.max(0, now - this.startTime);
    const elapsedSec = Math.floor(elapsedMs / 1000);

    let displaySeconds = 0;

    if (this.mode === "countdown") {
      const remainingSec = this.initialSeconds - elapsedSec;
      if (remainingSec <= 0) {
        displaySeconds = 0;
        this.stop();
        const formattedZero = AccurateTimer.formatTime(0);
        if (typeof this.onTick === "function") {
          this.onTick(formattedZero, 0);
        }
        if (typeof this.onComplete === "function") {
          this.onComplete();
        }
        return;
      }
      displaySeconds = remainingSec;
    } else {
      displaySeconds = elapsedSec;
    }

    const formatted = AccurateTimer.formatTime(displaySeconds);

    if (typeof this.onTick === "function") {
      this.onTick(formatted, displaySeconds);
    }
  }

  /**
   * Cleanly clear the active interval reference.
   */
  _clearInterval() {
    if (this.timerId !== null) {
      clearInterval(this.timerId);
      this.timerId = null;
    }
  }

  /**
   * Format seconds to HH:MM:SS or MM:SS (e.g. 00:01, 00:02).
   */
  static formatTime(totalSeconds) {
    const s = Math.max(0, Math.floor(totalSeconds));
    const mins = Math.floor(s / 60);
    const secs = s % 60;
    const hrs = Math.floor(mins / 60);
    const remMins = mins % 60;

    const pad = (n) => String(n).padStart(2, "0");

    if (hrs > 0) {
      return `${pad(hrs)}:${pad(remMins)}:${pad(secs)}`;
    }
    return `${pad(remMins)}:${pad(secs)}`;
  }
}

// Attach globally if in browser environment
if (typeof window !== "undefined") {
  window.AccurateTimer = AccurateTimer;
}

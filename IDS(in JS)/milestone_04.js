/*
 * Project: Cyber-Attack Detection in a Smart Home System
 * Group: Team_CyberPunks
 * Members: Mirihagalla M. K. D. M. 200397A, Pushpakumara S. N. 200489H, Thilakarathne D. L. J. 200650U, Satharasinghe S. A. P. U. 200589N
 * 
 * Description:
 * For this project milestone we aim to develop some functions for detecting anomalies in a smart home system. 
 * The system monitors and analyzes various activities (login attempts, device toggles, power usage, role changes, etc.) 
 * to identify potential security threats and alert the system administrators. 
 * Here in this code instance all the functions to analyze data and thresholds to identify anomaly detection
 * are defined.
 * 
 * Project Goal:
 * - To detect and filter malicious activities from normal activities within the smart home system.
 * - Provide detailed alerts and logs for further investigation.
 * 
 * Version: 1.0.6
 * Last Modified: 25/04/2025
 */


const fs = require('fs');

/**
 * Class to detect anomalous or potentially malicious behavior 
 * in a smart home system by analyzing attack signatures.
 */
class AttackDetector {
  constructor() 
  {
    this.loginAttempts = new Map();
    this.toggleEvents = new Map();
    this.roleChanges = new Map();
    this.powerAverages = new Map();
    this.store = new Map();
    this.logs = [];

    // Sample data for user IPs and private server IPs
    this.userIPs = 
    [
      "192.168.0.1", 
      "192.168.0.2", 
      "192.168.0.3", 
      "192.168.0.10", 
      "192.168.0.12", 
      "192.168.0.14", 
      "192.168.0.50", 
      "192.168.0.52", 
      "192.168.0.48", 
      "192.168.0.72"
    ];

    // Sample data for private server IPs
    this.private_server_IPs = 
    [
      "192.168.1.1", 
      "192.168.1.2", 
      "192.168.1.3"
    ];

    // Thresholds for various attack detection mechanisms
    this.thresholds = {
      maxFailedLogins: 5,
      loginWindowSec: 60,
      maxToggles: 10,
      toggleWindowSec: 30,
      powerSpikeMultiplier: 1.5,
      maxRoleChanges: 2,
      roleChangeWindowSec: 300,
      baseline_traffic: 8000 // In MB
    };
  }


  /**
   * Processes and analyzes an event.
   * @param {string} eventName - Event identification.
   * @param {string} userRole - User role causing the event.
   * @param {string} userId - Unique user ID.
   * @param {string} sourceId - Source device or endpoint ID.
   * @param {Date} timestamp - Event timestamp.
   * @param {object} context - Additional event context (e.g., success status, values).
   * @returns {object} logEntry - Log object containing event info and any alerts triggered.
   */
  instrument(
    eventName, 
    userRole, 
    userId, 
    sourceId, 
    timestamp, 
    context) 
    {
    const alertReasons = [];

    // ------------ Failed login attempts ------------
    if (eventName === 'login_attempt' && !context.success) {
      this._trackEvent(userId, timestamp, this.loginAttempts, this.thresholds.loginWindowSec);
      if (this._countRecent(
        userId, 
        timestamp, 
        this.loginAttempts, 
        this.thresholds.loginWindowSec) > this.thresholds.maxFailedLogins && !this._isPrivileged(userRole))
      {
        alertReasons.push(`Failed login attempts with sourceIP ${sourceId} threshold exceeded`);
      }
    }

    // ------------ Device toggle spam ------------
    if (eventName === 'toggle_device') {
      this._trackEvent(sourceId, timestamp, this.toggleEvents, this.thresholds.toggleWindowSec);
      if (this._countRecent(
        sourceId, 
        timestamp, 
        this.toggleEvents, 
        this.thresholds.toggleWindowSec) > this.thresholds.maxToggles) 
      {
        alertReasons.push('Device toggle frequency threshold exceeded');
      }
    }

    // ------------ Power reading anomalies ------------
    if (eventName === 'power_reading') {
      let value = context.value || 0;

      if (value === 0)
      {
        alertReasons.push('Zero power value detected');
      }

      if (value < 0) 
      {
        alertReasons.push('Negative power value');
        value = 0; // Normalize negative values to zero
      }

      const previousAvg = this.powerAverages.get(sourceId) || value;
      if (value > previousAvg * this.thresholds.powerSpikeMultiplier) 
      {
        alertReasons.push(`Power spike (${value.toFixed(1)} vs avg ${previousAvg.toFixed(1)})`);
      }

      this.powerAverages.set(sourceId, (previousAvg + value) / 2);
    }

    // ------------ After-working-hours access detection ------------
    if (eventName === 'access' && !this._isBusinessHours(context.value)) {
      if (!this._isPrivileged(userRole)) 
      {
        alertReasons.push('After-working-hours unprivileged access occured');
      }
    }

    // ------------ Role change frequency detection ------------
    if (context.prev_role) {
      this._trackEvent(userId, timestamp, this.roleChanges, this.thresholds.roleChangeWindowSec);
      if (this._countRecent(
        userId, 
        timestamp, 
        this.roleChanges, 
        this.thresholds.roleChangeWindowSec) > this.thresholds.maxRoleChanges) 
      {
        alertReasons.push(`Role update happened. (prev_role: ${context.prev_role}, updated_role: ${context.new_role})`);
      }
    }

    // ------------ Unusually large data traffic during non-working hours ------------
    if (eventName === 'unusual traffic patterns') {
      const value = context.value || 0;
      if (value > this.thresholds.baseline_traffic && !this._isBusinessHours(context.time)) 
      {
        alertReasons.push('Unusually large outbound traffic detected during non-working hours');
      }
    }

    // ------------ Unauthorized access for restricted resources ------------
    if (eventName === 'unauthorized access') {
      if (this.private_server_IPs.includes(sourceId) && !this._isPrivileged(userRole)) 
      {
        alertReasons.push('Unauthorized access to private server');
      }
    }



    const logEntry = {
      timestamp: timestamp.toISOString(),
      event: eventName,
      user: userId,
      source: sourceId,
      context,
      alert: alertReasons.length > 0,
      reasons: alertReasons
    };

    this.logs.push(logEntry);
    return logEntry;
  }

  /**
   * Tracks an event timestamp in a rolling window.
   * @param {string} key - Identifier for the user/device.
   * @param {Date} timestamp - Event occurance time.
   * @param {Map} store - Map to store the timestamps.
   * @param {number} windowSec - Time window in seconds.
   */
  _trackEvent(
    key, 
    timestamp, 
    store, 
    windowSec) 
  {
    const entries = store.get(key) || [];
    const cutoff = timestamp.getTime() - windowSec * 1000;
    entries.push(timestamp);
    store.set(key, entries.filter(t => t.getTime() > cutoff));
  }


  /**
   * Counts how many recent events occurred in the time window.
   * @param {string} key 
   * @param {Date} timestamp 
   * @param {Map} store 
   * @param {number} windowSec 
   * @returns {number}
   */
  _countRecent(
    key, 
    timestamp, 
    store, 
    windowSec) 
  {
    const entries = store.get(key) || [];
    const cutoff = timestamp.getTime() - windowSec * 1000;
    return entries.filter(t => t.getTime() > cutoff).length;
  }


  /**
   * Checks if a role has privileged access.
   * @param {string} role 
   * @returns {boolean}
   */
  _isPrivileged(role) 
  {
    return role === 'ADMIN' || role === 'MANAGER';
  }


  /**
   * Determines whether the current time falls within business hours.
   * @returns {boolean}
   */
  _isBusinessHours(currentTime = new Date()) 
  {
    const hour = currentTime.getHours();
    const minute = currentTime.getMinutes();
    return (hour > 8 || (hour === 8 && minute >= 30)) &&
          (hour < 17 || (hour === 17 && minute <= 30));
  }


/**
 *    
 * @param {string} userRole 
 * @param {string} sourceId 
 * @returns {boolean}
 */
  _isUnAuthorizedAccess(
    userRole, 
    sourceId) 
  {
    return !this._isPrivileged(userRole) && 
           !this.private_server_IPs.includes(sourceId);
  }


  /**
   * Saves all logged events to a file.
   * @param {string} filename 
   */
  saveLogs(filename) {
    fs.writeFileSync(filename, JSON.stringify(this.logs, null, 2));
  }
}

module.exports = AttackDetector;

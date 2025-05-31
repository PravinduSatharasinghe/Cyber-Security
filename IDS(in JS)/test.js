/*
 * Project: Cyber-Attack Detection in a Smart Home System
 * Group: Team_CyberPunks
 * Members: Mirihagalla M. K. D. M. 200397A, Pushpakumara S. N. 200489H, Thilakarathne D. L. J. 200650U, Satharasinghe S. A. P. U. 200589N
 * 
 * Description:
 * For this project milestone we aim to develop some functions for detecting anomalies in a smart home system. 
 * The system monitors and analyzes various activities (login attempts, device toggles, power usage, role changes, etc.) 
 * to identify potential security threats and alert the system administrators. 
 * Here in this code instance all the pre defined function in the 'milestone_04' code are tested
 * with simulated normal and malicious data.
 * 
 * Project Goal:
 * - To detect and filter malicious activities from normal activities within the smart home system.
 * - Provide detailed alerts and logs for further investigation.
 * 
 * Version: 1.0.6
 * Last Modified: 25/04/2025
 */

const fs = require('fs/promises');
const AttackDetector = require('./milestone_04'); //file including the AttackDetector class

/**
 * Simulate an event using the provided event details.
 * 
 * @param {Object} detector - Instance of AttackDetector to handle event detection.
 * @param {string} eventName - Name of the event being simulated.
 * @param {string} userRole - User role triggering the event.
 * @param {string} userId - User ID triggering the event.
 * @param {string} sourceId - Source ID/ device ID.
 * @param {Date} timestamp - The timestamp when the event occurs.
 * @param {Object} context - Additional context about the event.
 * @returns {Object} - The result of the event, potentially containing alerts.
 */
function simulateEvent(detector, eventName, userRole, userId, sourceId, timestamp, context) {
  return detector.instrument(eventName, userRole, userId, sourceId, timestamp, context);
}

/**
 * Run the event simulation to generate logs for various system activities.
 */
async function runSimulation() {
  // ------------ Initialize the attack detector ------------
  const detector = new AttackDetector(); 
  const alertsOnly = []; // Array to store only events that trigger alerts
  const baseTime = new Date(); // Initialize base timestamp for event simulation

  console.log("Starting Event Simulation...");

  let t = baseTime.getTime(); // Initialize time tracker

  // ------------ Simulate normal login attempts ------------
  console.log("Simulating normal login attempts...");
  for (let i = 0; i < 7; i++) {
    const interval = 5000 + Math.floor(Math.random() * 10000); // Random interval for each login attempt
    const log = simulateEvent(
      detector, 
      "login_attempt", 
      "ADMIN",
      "user123", 
      "192.168.0.2",
      new Date(t += interval * 1000), 
      {
      success: false
      });
    if (log.alert) alertsOnly.push(log); // Capture alert logs
  }


// ------------ Initialiing a brute-force login attempt ------------
console.log("Simulating brute-force login attempt...");

const attackerId = "attacker001";
const attackerIp = "10.0.0.1";

// ------------ Simulate failed login attempts with randomized timing ------------
for (let i = 0; i < 7; i++) {
  // Generate a random interval between 5s and 15s
  const interval = 5000 + Math.floor(Math.random() * 10000);
  t += interval;

  const timestamp = new Date(t);

  const log = simulateEvent(
    detector,
    "login_attempt",
    "USER",
    attackerId,
    attackerIp,
    timestamp,
    { success: false }
  );

  if (log.alert) alertsOnly.push(log);
}


  // ------------ Simulate device toggle spam (repeated toggling) ------------
  console.log("Simulating device toggle spam...");
  for (let i = 0; i < 12; i++) {
    const log = simulateEvent(
      detector, 
      "toggle_device", 
      "USER", 
      "user456", 
      "device_spam_1", 
      new Date(t += 2000), 
    {
      state: i % 2 === 0 ? "on" : "off"
    });
    if (log.alert) alertsOnly.push(log);
  }


  // ------------ Simulate a second device toggle spam ------------
  for (let i = 0; i < 12; i++) {
    const log = simulateEvent(
      detector, 
      "toggle_device", 
      "USER", 
      "user789", 
      "device_spam_2", 
      new Date(t += 2000), 
    {
      state: i % 2 === 0 ? "on" : "off"
    });
    if (log.alert) alertsOnly.push(log);
  }


  // ------------ Simulate power anomalies ------------
  console.log("Simulating power anomalies...");
  const powerVals = [0, -305, 295, 1400, 1350, 1500, 310, 290]; // Power readings with an anomaly included
  powerVals.forEach(val => {
    const log = simulateEvent(
      detector, 
      "power_reading", 
      "SYSTEM", 
      "sensor001", 
      "power_meter", 
      new Date(t += 3000), 
    {
      value: val
    });
    if (log.alert) alertsOnly.push(log);
  });


  // ------------ Simulate after-working-hours access attempts ------------
  console.log("Simulating after-working-hours access attempts...");
  const afterHoursTimes = [
    new Date(baseTime.setHours(1, 30)),
    new Date(baseTime.setHours(2, 0)),
    new Date(baseTime.setHours(23, 30)),
    new Date(baseTime.setHours(4, 15)),
    new Date(baseTime.setHours(22, 45))
  ];
  afterHoursTimes.forEach((time, i) => {
    const log = simulateEvent(
      detector, 
      "access", 
      "USER", 
      `user_night_${i}`, 
      `door${i + 1}`, 
      time, 
    {
      value: time
    });
    if (log.alert) alertsOnly.push(log);
  });


  // ------------ Simulate multiple role changes for the same user ------------
  console.log("Simulating multiple role changes...");
  const user1 = "changerHeavy1";
  const roles1 = ["MODERATOR", "ADMIN", "SUPERADMIN"];
  roles1.forEach((newRole, i) => {
    const log = simulateEvent(
      detector, 
      "login_attempt", 
      "USER", 
      user1, 
      "auth_gateway", 
      new Date(t += 60000), 
    {
      success: true,
      prev_role: "USER",
      new_role: newRole
    });
    if (log.alert) alertsOnly.push(log);
  });


  // ------------ Simulate multiple role changes for the same user ------------
  console.log("Simulating multiple role changes...");
  const user2 = "changerHeavy2";
  const roles2 = ["MODERATOR", "EDITOR"];
  roles2.forEach((newRole, i) => {
    const log = simulateEvent(
      detector, 
      "login_attempt", 
      "USER", 
      user2, 
      "auth_gateway", 
      new Date(t += 60000), 
    {
      success: true,
      prev_role: "VIEWER",
      new_role: newRole
    });
    if (log.alert) alertsOnly.push(log);
  });


  // ------------ Simulate unusual large data traffic ------------
  console.log("Simulating unusual large outbound data traffic...");
  const download_amount = [300, 600, 1200, 2400, 4800, 9600]; //  data traffic with an anomaly included
  const afterHoursTimes2 = new Date(baseTime.setHours(2, 30))

  download_amount.forEach(val => {
    const log = simulateEvent(
      detector, 
      "unusual traffic patterns", 
      "USER", 
      "user001", 
      "192.168.0.12", 
      new Date(t += 6000), 
    {
      value: val,
      time: afterHoursTimes2
    });
    if (log.alert) alertsOnly.push(log);
  });

  // ------------ Simulate unauthorized access for restricted resources ------------
  console.log("Simulating unauthorized access for restricted resources...");
    const log = simulateEvent(
      detector, 
      "unauthorized access", 
      "USER", "user001", 
      "192.168.1.2", 
      new Date(t += 600), {});
    if (log.alert) alertsOnly.push(log);


  // ------------ Save the logs to files ------------
  try {
    await fs.writeFile('alerts.json', JSON.stringify(alertsOnly, null, 2)); // Save alerts only
    await fs.writeFile('full_logs.json', JSON.stringify(detector.logs, null, 2)); // Save all logs
    console.log('Logs saved successfully:');
    console.log('- alerts.json (only logs with alerts)');
    console.log('- full_logs.json (all simulated events)');
  } catch (err) {
    console.error("Error saving logs:", err); // Handle potential errors while saving files
  }
}


// ------------ Run the simulation ------------
runSimulation().catch(err => {
  console.error("Error during simulation:", err);
});

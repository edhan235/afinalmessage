// A Final Message - Complete Implementation with Check-in System, Testing, CRUD, and Admin Authentication
const express = require("express");
const path = require("path");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const validator = require("validator");
const fs = require("fs");
const cron = require("node-cron");
const PDFDocument = require("pdfkit");
const crypto = require("crypto");

// JSON file database wrapper
class JSONFileDB {
  constructor() {
    this.dbPath = path.join(__dirname, "database.json");
    this.data = {};

    // Load existing data if file exists
    try {
      if (fs.existsSync(this.dbPath)) {
        const fileContent = fs.readFileSync(this.dbPath, "utf8");
        this.data = JSON.parse(fileContent);
        console.log("📦 Database loaded from database.json");
      } else {
        this.saveToFile();
        console.log("📦 New database created at database.json");
      }
    } catch (error) {
      console.log("📦 Creating new database");
      this.saveToFile();
    }
  }

  saveToFile() {
    try {
      fs.writeFileSync(this.dbPath, JSON.stringify(this.data, null, 2));
    } catch (error) {
      console.error("Error saving database:", error);
    }
  }

  async set(key, value) {
    this.data[key] = value;
    this.saveToFile();
    console.log(`💾 Saved to DB: ${key}`);
    return value;
  }

  async get(key) {
    const value = this.data[key];
    console.log(
      `📖 Retrieved from DB: ${key} = ${value ? "found" : "not found"}`
    );
    return value;
  }

  async delete(key) {
    delete this.data[key];
    this.saveToFile();
    console.log(`🗑️ Deleted from DB: ${key}`);
  }

  async list() {
    return Object.keys(this.data);
  }

  async getAll() {
    return this.data;
  }
}

const db = new JSONFileDB();

// External services
const twilio = require("twilio");
const sgMail = require("@sendgrid/mail");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 3000;

// Admin credentials (in production, use environment variables)
const ADMIN_CREDENTIALS = {
  username: "Northwestern",
  password: "458SShoreline",
};

// Middleware - ORDER MATTERS: These must come before routes
app.use(
  helmet({
    contentSecurityPolicy: false, // Disable CSP temporarily for testing
  })
);

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use("/signup", express.static("signup"));

// Session management
app.use(
  session({
    secret: process.env.SESSION_SECRET || "your-secret-key-change-this",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Set to true in production with HTTPS
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later.",
});
app.use("/api/", limiter);

// Configuration
const config = {
  twilio: {
    accountSid: process.env.TWILIO_ACCOUNT_SID,
    authToken: process.env.TWILIO_AUTH_TOKEN,
    phoneNumber: process.env.TWILIO_PHONE_NUMBER,
  },
  sendgrid: {
    apiKey: process.env.SENDGRID_API_KEY,
    fromEmail: process.env.FROM_EMAIL || "care@afinalmessage.com",
  },
};

// Initialize SendGrid
if (config.sendgrid.apiKey) {
  sgMail.setApiKey(config.sendgrid.apiKey);
}

// ===== HELPER FUNCTIONS =====

// Generate secure token for check-in links
function generateCheckInToken() {
  return crypto.randomBytes(32).toString("hex");
}

// Calculate next check-in date
function calculateNextCheckIn(startDate, frequencyMonths) {
  const start = new Date(startDate);
  const nextCheckIn = new Date(start);
  nextCheckIn.setMonth(start.getMonth() + frequencyMonths);
  return nextCheckIn.toISOString();
}

// Send check-in reminder (demo mode for now)
async function sendCheckInReminder(user, attemptNumber = 1) {
  const token = generateCheckInToken();
  const tokenExpiry = new Date();
  tokenExpiry.setDate(tokenExpiry.getDate() + 30); // 30 day expiry

  // Save token to database
  await db.set(`checkin_token:${token}`, {
    userId: user.id,
    created: new Date().toISOString(),
    expires: tokenExpiry.toISOString(),
    used: false,
  });

  const checkInUrl = `${
    process.env.APP_URL || "http://localhost:3000"
  }/checkin/${user.id}/${token}`;

  // Send SMS (demo mode)
  console.log(`📱 DEMO MODE - Check-in SMS to ${user.phone}:`);
  console.log(
    `Hi ${user.name}, it's time for your A Final Message check-in (Attempt ${attemptNumber}/3). Click here to confirm you're okay: ${checkInUrl}`
  );

  // Send Email (demo mode)
  console.log(`📧 DEMO MODE - Check-in Email to ${user.email}:`);
  console.log(
    `Subject: Your A Final Message Check-in (Attempt ${attemptNumber}/3)`
  );
  console.log(
    `Body: Hi ${user.name}, please click this link to confirm you're okay: ${checkInUrl}`
  );

  return token;
}

// Send final alert when user misses all check-ins
async function sendFinalAlert(user) {
  // Get inner circle and important contacts
  const allKeys = await db.list();

  const innerCircleContacts = [];
  const innerCircleKeys = allKeys.filter((key) =>
    key.startsWith(`inner_circle:${user.id}:`)
  );
  for (const key of innerCircleKeys) {
    const contact = await db.get(key);
    if (contact) innerCircleContacts.push(contact);
  }

  const importantContacts = [];
  const importantKeys = allKeys.filter((key) =>
    key.startsWith(`important_contact:${user.id}:`)
  );
  for (const key of importantKeys) {
    const contact = await db.get(key);
    if (contact) importantContacts.push(contact);
  }

  // Send email to care@afinalmessage.com (demo mode)
  console.log(`🚨 DEMO MODE - FINAL ALERT EMAIL to care@afinalmessage.com:`);
  console.log(`Subject: User ${user.name} has missed all check-ins`);
  console.log(`Body:`);
  console.log(
    `User ${user.name} (${user.phone}, ${user.email}) has missed all 3 check-in attempts.`
  );
  console.log(`\nInner Circle Contacts:`);
  innerCircleContacts.forEach((c) => {
    console.log(`- ${c.name}: ${c.phone} / ${c.email}`);
    if (c.personal_message)
      console.log(`  Personal Message: "${c.personal_message}"`);
  });
  console.log(`\nImportant Contacts:`);
  importantContacts.forEach((c) => {
    console.log(`- ${c.contact_type}: ${c.name} (${c.organization})`);
    console.log(`  ${c.phone} / ${c.email}`);
  });

  // Mark user as inactive
  user.subscription_status = "inactive";
  user.final_alert_sent = new Date().toISOString();
  await db.set(`userId:${user.id}`, user);
  await db.set(`user:${user.phone}`, user);
}

// Generate PDF for inner circle export
async function generateInnerCirclePDF(user) {
  const doc = new PDFDocument();
  const buffers = [];

  doc.on("data", buffers.push.bind(buffers));

  return new Promise(async (resolve, reject) => {
    doc.on("end", () => {
      const pdfData = Buffer.concat(buffers);
      resolve(pdfData);
    });

    // Get all contacts
    const allKeys = await db.list();

    const innerCircleContacts = [];
    const innerCircleKeys = allKeys.filter((key) =>
      key.startsWith(`inner_circle:${user.id}:`)
    );
    for (const key of innerCircleKeys) {
      const contact = await db.get(key);
      if (contact) innerCircleContacts.push(contact);
    }

    const importantContacts = [];
    const importantKeys = allKeys.filter((key) =>
      key.startsWith(`important_contact:${user.id}:`)
    );
    for (const key of importantKeys) {
      const contact = await db.get(key);
      if (contact) importantContacts.push(contact);
    }

    // Build PDF
    doc.fontSize(20).text("A Final Message", { align: "center" });
    doc
      .fontSize(16)
      .text(`Contact Information for ${user.name}`, { align: "center" });
    doc.moveDown();

    doc.fontSize(14).text("Inner Circle Contacts:", { underline: true });
    doc.moveDown();

    innerCircleContacts.forEach((contact, index) => {
      doc.fontSize(12).text(`Contact ${index + 1}:`, { bold: true });
      doc.fontSize(11);
      doc.text(`Name: ${contact.name}`);
      doc.text(`Phone: ${contact.phone || "Not provided"}`);
      doc.text(`Email: ${contact.email || "Not provided"}`);
      if (contact.personal_message) {
        doc.text(`Personal Message: "${contact.personal_message}"`);
      }
      doc.moveDown();
    });

    doc.addPage();
    doc.fontSize(14).text("Important Contacts:", { underline: true });
    doc.moveDown();

    importantContacts.forEach((contact, index) => {
      doc.fontSize(12).text(`${contact.contact_type}:`, { bold: true });
      doc.fontSize(11);
      doc.text(`Name: ${contact.name}`);
      if (contact.organization)
        doc.text(`Organization: ${contact.organization}`);
      doc.text(`Phone: ${contact.phone || "Not provided"}`);
      doc.text(`Email: ${contact.email || "Not provided"}`);
      doc.moveDown();
    });

    doc.end();
  });
}

// ===== MIDDLEWARE FUNCTIONS =====

// Admin authentication middleware
function requireAdminAuth(req, res, next) {
  if (req.session && req.session.isAdmin) {
    return next();
  } else {
    // Redirect to admin login
    res.redirect("/admin-login");
  }
}

// Initialize existing users with check-in fields (run once on startup)
async function initializeExistingUsers() {
  try {
    const allData = await db.getAll();
    const userKeys = Object.keys(allData).filter((k) =>
      k.startsWith("userId:")
    );

    let updatedCount = 0;

    for (const key of userKeys) {
      const user = allData[key];

      // Check if user already has check-in fields
      if (!user.check_in_frequency) {
        // Add default check-in fields
        const updatedUser = {
          ...user,
          check_in_frequency: 3, // Default 3 months
          subscription_start_date: user.created_at, // Use created_at as subscription start
          next_check_in_due: calculateNextCheckIn(user.created_at, 3),
          missed_check_ins: 0,
          last_check_in_date: null,
          updated_at: new Date().toISOString(),
        };

        // Update all user records
        await db.set(`userId:${user.id}`, updatedUser);
        await db.set(`user:${user.phone}`, updatedUser);

        updatedCount++;
      }
    }

    if (updatedCount > 0) {
      console.log(
        `🔄 Initialized ${updatedCount} existing users with check-in fields`
      );
    }
  } catch (error) {
    console.error("Error initializing existing users:", error);
  }
}

// ===== CRON JOB FOR CHECK-INS =====

// Run daily at midnight PST (8 AM UTC)
cron.schedule("0 8 * * *", async () => {
  console.log("🕐 Running daily check-in verification at midnight PST");

  try {
    const allData = await db.getAll();
    const userKeys = Object.keys(allData).filter((k) =>
      k.startsWith("userId:")
    );
    const today = new Date();

    for (const key of userKeys) {
      const user = allData[key];

      // Skip inactive users
      if (user.subscription_status !== "active") continue;

      const nextCheckIn = new Date(user.next_check_in_due);

      // Check if check-in is due
      if (nextCheckIn <= today) {
        console.log(`📅 Check-in due for ${user.name}`);

        // Determine which attempt this is
        const missedCount = user.missed_check_ins || 0;

        if (missedCount === 0) {
          // First attempt
          await sendCheckInReminder(user, 1);
          user.missed_check_ins = 1;
          user.last_reminder_sent = today.toISOString();
        } else if (missedCount === 1) {
          // Check if 7 days have passed since last reminder
          const lastReminder = new Date(user.last_reminder_sent);
          const daysSinceReminder = Math.floor(
            (today - lastReminder) / (1000 * 60 * 60 * 24)
          );

          if (daysSinceReminder >= 7) {
            await sendCheckInReminder(user, 2);
            user.missed_check_ins = 2;
            user.last_reminder_sent = today.toISOString();
          }
        } else if (missedCount === 2) {
          // Check if 7 days have passed since last reminder
          const lastReminder = new Date(user.last_reminder_sent);
          const daysSinceReminder = Math.floor(
            (today - lastReminder) / (1000 * 60 * 60 * 24)
          );

          if (daysSinceReminder >= 7) {
            await sendCheckInReminder(user, 3);
            user.missed_check_ins = 3;
            user.last_reminder_sent = today.toISOString();
          }
        } else if (missedCount >= 3) {
          // Check if 7 days have passed since last reminder
          const lastReminder = new Date(user.last_reminder_sent);
          const daysSinceReminder = Math.floor(
            (today - lastReminder) / (1000 * 60 * 60 * 24)
          );

          if (daysSinceReminder >= 7 && !user.final_alert_sent) {
            // Send final alert
            console.log(`🚨 Sending final alert for ${user.name}`);
            await sendFinalAlert(user);
          }
        }

        // Save updated user
        await db.set(`userId:${user.id}`, user);
        await db.set(`user:${user.phone}`, user);
      }
    }
  } catch (error) {
    console.error("Error in check-in cron job:", error);
  }
});

// ===== ROUTES =====

// Homepage route
//app.get("/", (req, res) => {
//res.send(`
//    <!DOCTYPE html>
//  <html>
//<head>
//  <title>A Final Message</title>
//<style>
//  body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; text-align: center; }
//.btn { background: #007cba; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-size: 18px; margin: 10px; display: inline-block; }
//.btn:hover { background: #005a8b; }
//h1 { color: #333; margin-bottom: 20px; }
//p { color: #666; margin-bottom: 30px; }
//</style>
//</head>
//<body>
//  <h1>A Final Message</h1>
//  <p>Ensure your final words reach your loved ones when you can no longer deliver them yourself</p>
//<a href="/signup" class="btn">Create Your Final Message</a>
//<br><br>
//<a href="/login" class="btn" style="background: #6c757d;">Login to Your Account</a>
//</body>
//</html>
//`);
//});

// Signup routes
app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "signup", "nameandphone.html"));
});

app.get("/signup/nameandphone.html", (req, res) => {
  res.sendFile(path.join(__dirname, "signup", "nameandphone.html"));
});

app.get("/signup/phoneverification.html", (req, res) => {
  res.sendFile(path.join(__dirname, "signup", "phoneverification.html"));
});

app.get("/signup/emailaddress.html", (req, res) => {
  res.sendFile(path.join(__dirname, "signup", "emailaddress.html"));
});

app.get("/signup/emailverification.html", (req, res) => {
  res.sendFile(path.join(__dirname, "signup", "emailverification.html"));
});

app.get("/signup/payment.html", (req, res) => {
  res.sendFile(path.join(__dirname, "signup", "payment.html"));
});

app.get("/signup/innercirclecontact.html", (req, res) => {
  res.sendFile(path.join(__dirname, "signup", "innercirclecontact.html"));
});

app.get("/signup/importantcontact.html", (req, res) => {
  res.sendFile(path.join(__dirname, "signup", "importantcontact.html"));
});

// Account route
app.get("/account", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "account.html"));
});

// Login route
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Admin login route
app.get("/admin-login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin-login.html"));
});

// Check-in route
app.get("/checkin/:userId/:token", async (req, res) => {
  res.sendFile(path.join(__dirname, "public", "checkin.html"));
});

// ===== API ENDPOINTS =====

// Send phone verification during signup
app.post("/api/signup/send-phone-verification", async (req, res) => {
  try {
    const { name, phone } = req.body;
    const fullPhone = `+1${phone}`;

    console.log("Sending phone verification:", { name, fullPhone });

    // Check if user already exists
    const existingUser = await db.get(`user:${fullPhone}`);
    if (existingUser) {
      return res.status(409).json({
        error: "Account already exists with this phone number",
        redirect: "/login",
      });
    }

    // Generate 6-digit verification code
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    // Save verification code with expiration
    await db.set(`phone_verification:${fullPhone}`, {
      code: code,
      name: name,
      expires: Date.now() + 10 * 60 * 1000, // 10 minutes
      attempts: 0,
    });

    // Send SMS via Twilio (demo mode for now)
    console.log(
      `📱 DEMO MODE - Phone verification code for ${fullPhone}: ${code}`
    );

    res.json({
      success: true,
      message: "Verification code sent to your phone",
    });
  } catch (error) {
    console.error("Phone verification error:", error);
    res
      .status(500)
      .json({ error: "Failed to send verification code. Please try again." });
  }
});

// Verify phone during signup
app.post("/api/signup/verify-phone", async (req, res) => {
  try {
    const { phone, code } = req.body;

    console.log("Verifying phone:", { phone, code });

    const verification = await db.get(`phone_verification:${phone}`);

    if (!verification) {
      return res.status(400).json({
        error: "No verification code found. Please request a new code.",
      });
    }

    if (Date.now() > verification.expires) {
      return res.status(400).json({
        error: "Verification code expired. Please request a new code.",
      });
    }

    if (verification.code !== code) {
      verification.attempts = (verification.attempts || 0) + 1;
      await db.set(`phone_verification:${phone}`, verification);

      if (verification.attempts >= 3) {
        return res.status(400).json({
          error: "Too many failed attempts. Please request a new code.",
        });
      }

      return res
        .status(400)
        .json({ error: "Invalid verification code. Please try again." });
    }

    // Mark phone as verified
    await db.set(`phone_verified:${phone}`, {
      verified: true,
      name: verification.name,
      verifiedAt: new Date().toISOString(),
    });

    res.json({ success: true, message: "Phone verified successfully" });
  } catch (error) {
    console.error("Phone verify error:", error);
    res.status(500).json({ error: "Verification failed. Please try again." });
  }
});

// Send email verification during signup
app.post("/api/signup/send-email-verification", async (req, res) => {
  try {
    const { email } = req.body;

    console.log("Sending email verification:", { email });

    if (!validator.isEmail(email)) {
      return res
        .status(400)
        .json({ error: "Please enter a valid email address" });
    }

    // Generate 6-digit verification code
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    // Save verification code
    await db.set(`email_verification:${email}`, {
      code: code,
      expires: Date.now() + 10 * 60 * 1000, // 10 minutes
      attempts: 0,
    });

    // Send email (demo mode for now)
    console.log(`📧 DEMO MODE - Email verification code for ${email}: ${code}`);

    res.json({
      success: true,
      message: "Verification code sent to your email",
    });
  } catch (error) {
    console.error("Email verification error:", error);
    res
      .status(500)
      .json({ error: "Failed to send verification code. Please try again." });
  }
});

// Verify email during signup
app.post("/api/signup/verify-email", async (req, res) => {
  try {
    const { email, code } = req.body;

    console.log("Verifying email:", { email, code });

    const verification = await db.get(`email_verification:${email}`);

    if (!verification) {
      return res.status(400).json({
        error: "No verification code found. Please request a new code.",
      });
    }

    if (Date.now() > verification.expires) {
      return res.status(400).json({
        error: "Verification code expired. Please request a new code.",
      });
    }

    if (verification.code !== code) {
      verification.attempts = (verification.attempts || 0) + 1;
      await db.set(`email_verification:${email}`, verification);

      if (verification.attempts >= 3) {
        return res.status(400).json({
          error: "Too many failed attempts. Please request a new code.",
        });
      }

      return res
        .status(400)
        .json({ error: "Invalid verification code. Please try again." });
    }

    // Mark email as verified
    await db.set(`email_verified:${email}`, {
      verified: true,
      verifiedAt: new Date().toISOString(),
    });

    res.json({ success: true, message: "Email verified successfully" });
  } catch (error) {
    console.error("Email verify error:", error);
    res.status(500).json({ error: "Verification failed. Please try again." });
  }
});

// Process payment during signup (demo mode)
app.post("/api/signup/process-payment", async (req, res) => {
  try {
    const { paymentMethodId, name, email, phone } = req.body;

    console.log("💳 DEMO MODE - Payment processed successfully for:", {
      name,
      email,
      phone,
    });

    // Simulate successful payment
    res.json({
      success: true,
      customerId: "cus_demo_" + Date.now(),
      subscriptionId: "sub_demo_" + Date.now(),
    });
  } catch (error) {
    console.error("Payment processing error:", error);
    res
      .status(500)
      .json({ error: "Payment processing failed. Please try again." });
  }
});

// Complete the entire signup process
app.post("/api/signup/complete-signup", async (req, res) => {
  try {
    const {
      name,
      phone,
      email,
      customerId,
      subscriptionId,
      timezone,
      innerCircleContact,
      importantContact,
    } = req.body;

    console.log("Completing signup for:", { name, phone, email });

    // Generate unique user ID
    const userId = uuidv4();
    const now = new Date().toISOString();

    // Create user record with check-in fields
    const userData = {
      id: userId,
      name: name,
      phone: phone,
      email: email,
      stripe_customer_id: customerId,
      stripe_subscription_id: subscriptionId,
      timezone: timezone || "America/New_York",
      is_active: true,
      subscription_status: "active",
      // Check-in fields
      check_in_frequency: 3, // Default 3 months for new users
      subscription_start_date: now,
      next_check_in_due: calculateNextCheckIn(now, 3),
      missed_check_ins: 0,
      last_check_in_date: null,
      created_at: now,
      updated_at: now,
    };

    // Save user to database
    await db.set(`user:${phone}`, userData);
    await db.set(`email:${email}`, { userId: userId, phone: phone });
    await db.set(`userId:${userId}`, userData);

    // Save inner circle contact if provided
    if (innerCircleContact && innerCircleContact.name) {
      const innerCircleId = uuidv4();
      await db.set(`inner_circle:${userId}:${innerCircleId}`, {
        id: innerCircleId,
        user_id: userId,
        name: innerCircleContact.name,
        phone: innerCircleContact.phone || "",
        email: innerCircleContact.email || "",
        personal_message: innerCircleContact.message || "",
        created_at: now,
      });
    }

    // Save important contact if provided
    if (importantContact && importantContact.name) {
      const importantContactId = uuidv4();
      await db.set(`important_contact:${userId}:${importantContactId}`, {
        id: importantContactId,
        user_id: userId,
        contact_type: importantContact.type || "Other",
        name: importantContact.name,
        organization: importantContact.organization || "",
        phone: importantContact.phone || "",
        email: importantContact.email || "",
        created_at: now,
      });
    }

    // Store user session
    req.session.userId = userId;
    req.session.userPhone = phone;
    req.session.userEmail = email;

    // Clean up verification records
    await db.delete(`phone_verification:${phone}`);
    await db.delete(`phone_verified:${phone}`);
    await db.delete(`email_verification:${email}`);
    await db.delete(`email_verified:${email}`);

    console.log("✅ User created successfully:", userId);

    res.json({
      success: true,
      message: "Account created successfully!",
      userId: userId,
    });
  } catch (error) {
    console.error("Complete signup error:", error);
    res.status(500).json({
      error:
        "Failed to create account. Please contact support if this continues.",
    });
  }
});

// Resend verification codes during signup
app.post("/api/signup/resend-code", async (req, res) => {
  try {
    const { identifier, type } = req.body;

    console.log("Resending code:", { identifier, type });

    // Generate new code
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    if (type === "phone") {
      // Update phone verification
      const existing = await db.get(`phone_verification:${identifier}`);
      if (existing) {
        await db.set(`phone_verification:${identifier}`, {
          ...existing,
          code: code,
          expires: Date.now() + 10 * 60 * 1000,
          attempts: 0,
        });

        console.log(
          `📱 DEMO MODE - Resent phone code for ${identifier}: ${code}`
        );
      }
    } else if (type === "email") {
      // Update email verification
      const existing = await db.get(`email_verification:${identifier}`);
      if (existing) {
        await db.set(`email_verification:${identifier}`, {
          ...existing,
          code: code,
          expires: Date.now() + 10 * 60 * 1000,
          attempts: 0,
        });

        console.log(
          `📧 DEMO MODE - Resent email code for ${identifier}: ${code}`
        );
      }
    }

    res.json({ success: true, message: "New verification code sent" });
  } catch (error) {
    console.error("Resend code error:", error);
    res
      .status(500)
      .json({ error: "Failed to resend verification code. Please try again." });
  }
});

// ===== ENHANCED LOGIN ENDPOINTS WITH TWO-STEP VERIFICATION =====

// Step 1: Send phone verification for login
app.post("/api/login/send-phone-verification", async (req, res) => {
  try {
    const { phone } = req.body;

    console.log("Login phone verification request for:", phone);

    if (!phone) {
      return res.status(400).json({
        success: false,
        error: "Phone number is required",
      });
    }

    // Check if user exists
    const userData = await db.get(`user:${phone}`);

    if (!userData) {
      console.log("User not found for phone:", phone);
      return res.status(404).json({
        success: false,
        error: "No account found with this phone number. Please sign up first.",
      });
    }

    // Generate 6-digit verification code
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    // Save verification code with expiration
    await db.set(`login_phone_verification:${phone}`, {
      code: code,
      userId: userData.id,
      expires: Date.now() + 10 * 60 * 1000, // 10 minutes
      attempts: 0,
    });

    // Send SMS via Twilio (demo mode for now)
    console.log(
      `📱 DEMO MODE - Login phone verification code for ${phone}: ${code}`
    );

    res.json({
      success: true,
      message: "Verification code sent to your phone",
    });
  } catch (error) {
    console.error("Login phone verification error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to send verification code. Please try again.",
    });
  }
});

// Step 2: Verify phone and send email verification for login
app.post("/api/login/verify-phone", async (req, res) => {
  try {
    const { phone, code } = req.body;

    console.log("Login phone verification:", { phone, code });

    const verification = await db.get(`login_phone_verification:${phone}`);

    if (!verification) {
      return res.status(400).json({
        success: false,
        error: "No verification code found. Please request a new code.",
      });
    }

    if (Date.now() > verification.expires) {
      return res.status(400).json({
        success: false,
        error: "Verification code expired. Please request a new code.",
      });
    }

    if (verification.code !== code) {
      verification.attempts = (verification.attempts || 0) + 1;
      await db.set(`login_phone_verification:${phone}`, verification);

      if (verification.attempts >= 3) {
        return res.status(400).json({
          success: false,
          error: "Too many failed attempts. Please request a new code.",
        });
      }

      return res.status(400).json({
        success: false,
        error: "Invalid verification code. Please try again.",
      });
    }

    // Get user data
    const userData = await db.get(`userId:${verification.userId}`);
    if (!userData) {
      return res.status(404).json({
        success: false,
        error: "User account not found",
      });
    }

    // Generate email verification code
    const emailCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Save email verification code
    await db.set(`login_email_verification:${userData.email}`, {
      code: emailCode,
      userId: userData.id,
      phone: phone,
      expires: Date.now() + 10 * 60 * 1000, // 10 minutes
      attempts: 0,
    });

    // Send email (demo mode for now)
    console.log(
      `📧 DEMO MODE - Login email verification code for ${userData.email}: ${emailCode}`
    );

    // Clean up phone verification
    await db.delete(`login_phone_verification:${phone}`);

    res.json({
      success: true,
      message: "Phone verified. Email verification code sent.",
      email: userData.email,
    });
  } catch (error) {
    console.error("Login phone verify error:", error);
    res.status(500).json({
      success: false,
      error: "Verification failed. Please try again.",
    });
  }
});

// Step 3: Verify email and complete login
app.post("/api/login/verify-email", async (req, res) => {
  try {
    const { email, code } = req.body;

    console.log("Login email verification:", { email, code });

    const verification = await db.get(`login_email_verification:${email}`);

    if (!verification) {
      return res.status(400).json({
        success: false,
        error: "No verification code found. Please request a new code.",
      });
    }

    if (Date.now() > verification.expires) {
      return res.status(400).json({
        success: false,
        error: "Verification code expired. Please request a new code.",
      });
    }

    if (verification.code !== code) {
      verification.attempts = (verification.attempts || 0) + 1;
      await db.set(`login_email_verification:${email}`, verification);

      if (verification.attempts >= 3) {
        return res.status(400).json({
          success: false,
          error: "Too many failed attempts. Please request a new code.",
        });
      }

      return res.status(400).json({
        success: false,
        error: "Invalid verification code. Please try again.",
      });
    }

    // Get user data
    const userData = await db.get(`userId:${verification.userId}`);
    if (!userData) {
      return res.status(404).json({
        success: false,
        error: "User account not found",
      });
    }

    // Create session
    req.session.userId = userData.id;
    req.session.userPhone = verification.phone;
    req.session.userEmail = email;

    console.log(
      "User logged in successfully:",
      userData.name,
      "ID:",
      userData.id
    );

    // Clean up email verification
    await db.delete(`login_email_verification:${email}`);

    // Return success response
    res.json({
      success: true,
      message: "Login successful",
      user: {
        name: userData.name,
        phone: userData.phone,
        email: userData.email,
      },
    });
  } catch (error) {
    console.error("Login email verify error:", error);
    res.status(500).json({
      success: false,
      error: "Verification failed. Please try again.",
    });
  }
});

// Resend phone code during login
app.post("/api/login/resend-phone-code", async (req, res) => {
  try {
    const { phone } = req.body;

    console.log("Resending login phone code for:", phone);

    // Check if user exists
    const userData = await db.get(`user:${phone}`);
    if (!userData) {
      return res.status(404).json({
        success: false,
        error: "No account found with this phone number.",
      });
    }

    // Generate new code
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    // Update verification record
    await db.set(`login_phone_verification:${phone}`, {
      code: code,
      userId: userData.id,
      expires: Date.now() + 10 * 60 * 1000,
      attempts: 0,
    });

    console.log(`📱 DEMO MODE - Resent login phone code for ${phone}: ${code}`);

    res.json({
      success: true,
      message: "New verification code sent to your phone",
    });
  } catch (error) {
    console.error("Resend login phone code error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to resend verification code. Please try again.",
    });
  }
});

// Resend email code during login
app.post("/api/login/resend-email-code", async (req, res) => {
  try {
    const { email } = req.body;

    console.log("Resending login email code for:", email);

    // Check if there's an existing email verification
    const existing = await db.get(`login_email_verification:${email}`);
    if (!existing) {
      return res.status(400).json({
        success: false,
        error: "No email verification session found.",
      });
    }

    // Generate new code
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    // Update verification record
    await db.set(`login_email_verification:${email}`, {
      ...existing,
      code: code,
      expires: Date.now() + 10 * 60 * 1000,
      attempts: 0,
    });

    console.log(`📧 DEMO MODE - Resent login email code for ${email}: ${code}`);

    res.json({
      success: true,
      message: "New verification code sent to your email",
    });
  } catch (error) {
    console.error("Resend login email code error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to resend verification code. Please try again.",
    });
  }
});

// Keep the original simple login endpoint for backward compatibility (optional)
// You can remove this if you want to force two-step verification for all logins
app.post("/api/login", async (req, res) => {
  console.log(
    "DEPRECATED LOGIN ENDPOINT - Redirecting to two-step verification"
  );

  // Redirect to the new flow
  res.status(302).json({
    success: false,
    error: "Please use the new secure login process",
    redirect: "/login",
  });
});

// Logout endpoint
app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ error: "Failed to logout" });
    }
    console.log("User logged out successfully");
    res.json({ success: true, message: "Logged out successfully" });
  });
});

// ===== ADMIN AUTHENTICATION ENDPOINTS =====

// Admin login endpoint
app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    console.log("Admin login attempt:", username);

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: "Username and password are required",
      });
    }

    // Check credentials
    if (
      username === ADMIN_CREDENTIALS.username &&
      password === ADMIN_CREDENTIALS.password
    ) {
      // Create admin session
      req.session.isAdmin = true;
      req.session.adminUsername = username;
      req.session.adminLoginTime = new Date().toISOString();

      console.log("✅ Admin login successful:", username);

      res.json({
        success: true,
        message: "Admin login successful",
      });
    } else {
      console.log("❌ Admin login failed: Invalid credentials");
      res.status(401).json({
        success: false,
        error: "Invalid username or password",
      });
    }
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({
      success: false,
      error: "Login failed. Please try again.",
    });
  }
});

// Admin logout endpoint
app.post("/api/admin/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Admin logout error:", err);
      return res.status(500).json({ error: "Failed to logout" });
    }
    console.log("Admin logged out successfully");
    res.json({ success: true, message: "Admin logged out successfully" });
  });
});

// Cancel user account (admin only)
app.post(
  "/api/admin/cancel-account/:userId",
  requireAdminAuth,
  async (req, res) => {
    try {
      const { userId } = req.params;

      const user = await db.get(`userId:${userId}`);
      if (!user) {
        return res
          .status(404)
          .json({ success: false, error: "User not found" });
      }

      // Cancel Stripe subscription (demo mode)
      if (user.stripe_subscription_id) {
        console.log(
          `💳 DEMO MODE - Cancelling Stripe subscription: ${user.stripe_subscription_id}`
        );
        // In production: await stripe.subscriptions.cancel(user.stripe_subscription_id);
      }

      // Update user status
      user.subscription_status = "cancelled";
      user.cancelled_at = new Date().toISOString();
      user.cancelled_by = req.session.adminUsername;

      await db.set(`userId:${userId}`, user);
      await db.set(`user:${user.phone}`, user);

      console.log(
        `❌ Account cancelled for user ${user.name} by admin ${req.session.adminUsername}`
      );

      res.json({ success: true, message: "Account cancelled successfully" });
    } catch (error) {
      console.error("Cancel account error:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to cancel account" });
    }
  }
);

// Export user data as PDF (admin only)
app.get(
  "/api/admin/export-user-data/:userId",
  requireAdminAuth,
  async (req, res) => {
    try {
      const { userId } = req.params;

      const user = await db.get(`userId:${userId}`);
      if (!user) {
        return res
          .status(404)
          .json({ success: false, error: "User not found" });
      }

      const pdfBuffer = await generateInnerCirclePDF(user);

      res.setHeader("Content-Type", "application/pdf");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${user.name.replace(
          /\s+/g,
          "_"
        )}_InnerCircle_Data.pdf"`
      );
      res.send(pdfBuffer);
    } catch (error) {
      console.error("Export user data error:", error);
      res.status(500).json({ success: false, error: "Failed to export data" });
    }
  }
);

// ===== CHECK-IN SYSTEM ENDPOINTS =====

// Process check-in from link
app.post("/api/checkin/:userId/:token", async (req, res) => {
  try {
    const { userId, token } = req.params;

    // Verify token
    const tokenData = await db.get(`checkin_token:${token}`);
    if (!tokenData) {
      return res
        .status(400)
        .json({ success: false, error: "Invalid or expired check-in link" });
    }

    // Check if token is expired
    if (new Date(tokenData.expires) < new Date()) {
      return res
        .status(400)
        .json({ success: false, error: "Check-in link has expired" });
    }

    // Check if token was already used
    if (tokenData.used) {
      return res
        .status(400)
        .json({ success: false, error: "Check-in link has already been used" });
    }

    // Verify user ID matches
    if (tokenData.userId !== userId) {
      return res
        .status(400)
        .json({ success: false, error: "Invalid check-in link" });
    }

    // Get user
    const user = await db.get(`userId:${userId}`);
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    // Mark token as used
    tokenData.used = true;
    tokenData.used_at = new Date().toISOString();
    await db.set(`checkin_token:${token}`, tokenData);

    // Create check-in record
    const checkInId = uuidv4();
    const checkInRecord = {
      id: checkInId,
      user_id: userId,
      checked_in_at: new Date().toISOString(),
      method: "link",
      token: token,
    };
    await db.set(`checkin:${userId}:${checkInId}`, checkInRecord);

    // Update user record
    user.last_check_in_date = new Date().toISOString();
    user.missed_check_ins = 0; // Reset missed count
    user.next_check_in_due = calculateNextCheckIn(
      new Date().toISOString(),
      user.check_in_frequency
    );

    await db.set(`userId:${userId}`, user);
    await db.set(`user:${user.phone}`, user);

    console.log(`✅ Check-in successful for ${user.name}`);

    res.json({
      success: true,
      message: "Check-in successful! Thank you for confirming you're okay.",
      nextCheckIn: user.next_check_in_due,
    });
  } catch (error) {
    console.error("Check-in error:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to process check-in" });
  }
});

// Get check-in history for user
app.get("/api/account/checkin-history", async (req, res) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res
        .status(401)
        .json({ success: false, error: "Not authenticated" });
    }

    // Get all check-ins for this user
    const allKeys = await db.list();
    const checkInKeys = allKeys.filter((key) =>
      key.startsWith(`checkin:${userId}:`)
    );

    const checkIns = [];
    for (const key of checkInKeys) {
      const checkIn = await db.get(key);
      if (checkIn) checkIns.push(checkIn);
    }

    // Sort by date (newest first)
    checkIns.sort(
      (a, b) => new Date(b.checked_in_at) - new Date(a.checked_in_at)
    );

    res.json({ success: true, checkIns });
  } catch (error) {
    console.error("Get check-in history error:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to get check-in history" });
  }
});

// Update check-in frequency
app.post("/api/account/update-checkin-frequency", async (req, res) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res
        .status(401)
        .json({ success: false, error: "Not authenticated" });
    }

    const { frequency } = req.body;

    // Validate frequency
    if (![3, 6, 12].includes(frequency)) {
      return res.status(400).json({
        success: false,
        error: "Invalid frequency. Must be 3, 6, or 12 months.",
      });
    }

    // Get user
    const user = await db.get(`userId:${userId}`);
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    // Update frequency and recalculate next check-in
    const oldFrequency = user.check_in_frequency;
    user.check_in_frequency = frequency;

    // Recalculate next check-in based on last check-in or subscription start
    const baseDate = user.last_check_in_date || user.subscription_start_date;
    user.next_check_in_due = calculateNextCheckIn(baseDate, frequency);
    user.updated_at = new Date().toISOString();

    await db.set(`userId:${userId}`, user);
    await db.set(`user:${user.phone}`, user);

    console.log(
      `📅 Check-in frequency updated from ${oldFrequency} to ${frequency} months for ${user.name}`
    );

    res.json({
      success: true,
      message: `Check-in frequency updated to ${frequency} months`,
      nextCheckIn: user.next_check_in_due,
    });
  } catch (error) {
    console.error("Update check-in frequency error:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to update check-in frequency" });
  }
});

// Manual check-in (from account page)
app.post("/api/account/manual-checkin", async (req, res) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res
        .status(401)
        .json({ success: false, error: "Not authenticated" });
    }

    // Get user
    const user = await db.get(`userId:${userId}`);
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    // Create check-in record
    const checkInId = uuidv4();
    const checkInRecord = {
      id: checkInId,
      user_id: userId,
      checked_in_at: new Date().toISOString(),
      method: "manual",
    };
    await db.set(`checkin:${userId}:${checkInId}`, checkInRecord);

    // Update user record
    user.last_check_in_date = new Date().toISOString();
    user.missed_check_ins = 0; // Reset missed count
    user.next_check_in_due = calculateNextCheckIn(
      new Date().toISOString(),
      user.check_in_frequency
    );

    await db.set(`userId:${userId}`, user);
    await db.set(`user:${user.phone}`, user);

    console.log(`✅ Manual check-in successful for ${user.name}`);

    res.json({
      success: true,
      message: "Check-in successful!",
      nextCheckIn: user.next_check_in_due,
    });
  } catch (error) {
    console.error("Manual check-in error:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to process check-in" });
  }
});

// ===== TEST ENDPOINTS FOR CHECK-IN SYSTEM (REMOVE IN PRODUCTION) =====

// Manually trigger check-in reminder for a specific user (admin only)
app.post(
  "/api/admin/test/trigger-checkin/:userId",
  requireAdminAuth,
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { attemptNumber = 1 } = req.body;
      const user = await db.get(`userId:${userId}`);

      if (!user) {
        return res
          .status(404)
          .json({ success: false, error: "User not found" });
      }

      // Send reminder with specified attempt number
      await sendCheckInReminder(user, attemptNumber);

      console.log(
        `🧪 TEST: Triggered check-in attempt ${attemptNumber} for ${user.name}`
      );
      res.json({
        success: true,
        message: `Check-in reminder (attempt ${attemptNumber}) sent to ${user.name}`,
        phone: user.phone,
        email: user.email,
        checkConsoleLog: true,
      });
    } catch (error) {
      console.error("Test trigger error:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to trigger check-in" });
    }
  }
);

// Simulate missed check-ins (admin only)
app.post(
  "/api/admin/test/simulate-missed/:userId",
  requireAdminAuth,
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { count } = req.body;
      const missedCount = parseInt(count);

      if (missedCount < 0 || missedCount > 3) {
        return res.status(400).json({
          success: false,
          error: "Count must be between 0 and 3",
        });
      }

      const user = await db.get(`userId:${userId}`);
      if (!user) {
        return res
          .status(404)
          .json({ success: false, error: "User not found" });
      }

      // Set missed check-ins
      user.missed_check_ins = missedCount;
      user.next_check_in_due = new Date(Date.now() - 86400000).toISOString(); // Yesterday
      user.last_reminder_sent = new Date(
        Date.now() - 8 * 86400000
      ).toISOString(); // 8 days ago

      await db.set(`userId:${userId}`, user);
      await db.set(`user:${user.phone}`, user);

      console.log(
        `🧪 TEST: Set ${missedCount} missed check-ins for ${user.name}`
      );
      res.json({
        success: true,
        message: `Set ${missedCount} missed check-ins for ${user.name}`,
        nextAction:
          missedCount === 3
            ? "Ready to send final alert"
            : `Ready for attempt ${missedCount + 1}`,
      });
    } catch (error) {
      console.error("Test simulate error:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to simulate missed check-ins" });
    }
  }
);

// Send final alert immediately (admin only)
app.post(
  "/api/admin/test/send-final-alert/:userId",
  requireAdminAuth,
  async (req, res) => {
    try {
      const { userId } = req.params;
      const user = await db.get(`userId:${userId}`);

      if (!user) {
        return res
          .status(404)
          .json({ success: false, error: "User not found" });
      }

      // Send final alert
      await sendFinalAlert(user);

      console.log(`🧪 TEST: Sent final alert for ${user.name}`);
      res.json({
        success: true,
        message: `Final alert sent for ${user.name}. Check console for email content.`,
        checkConsoleLog: true,
      });
    } catch (error) {
      console.error("Test final alert error:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to send final alert" });
    }
  }
);

// Reset check-in status (admin only)
app.post(
  "/api/admin/test/reset-checkin/:userId",
  requireAdminAuth,
  async (req, res) => {
    try {
      const { userId } = req.params;
      const user = await db.get(`userId:${userId}`);

      if (!user) {
        return res
          .status(404)
          .json({ success: false, error: "User not found" });
      }

      // Reset all check-in fields
      user.missed_check_ins = 0;
      user.next_check_in_due = calculateNextCheckIn(
        new Date().toISOString(),
        user.check_in_frequency
      );
      user.last_check_in_date = new Date().toISOString();
      user.final_alert_sent = null;
      user.last_reminder_sent = null;

      await db.set(`userId:${userId}`, user);
      await db.set(`user:${user.phone}`, user);

      console.log(`🧪 TEST: Reset check-in status for ${user.name}`);
      res.json({
        success: true,
        message: `Check-in status reset for ${user.name}`,
        nextCheckIn: user.next_check_in_due,
      });
    } catch (error) {
      console.error("Test reset error:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to reset check-in status" });
    }
  }
);

// Get check-in test status (admin only)
app.get(
  "/api/admin/test/checkin-status/:userId",
  requireAdminAuth,
  async (req, res) => {
    try {
      const { userId } = req.params;
      const user = await db.get(`userId:${userId}`);

      if (!user) {
        return res
          .status(404)
          .json({ success: false, error: "User not found" });
      }

      // Get all check-in tokens for this user
      const allKeys = await db.list();
      const tokenKeys = allKeys.filter((key) =>
        key.startsWith("checkin_token:")
      );
      const activeTokens = [];

      for (const key of tokenKeys) {
        const token = await db.get(key);
        if (token && token.userId === userId && !token.used) {
          activeTokens.push({
            created: token.created,
            expires: token.expires,
            url: `/checkin/${userId}/${key.split(":")[1]}`,
          });
        }
      }

      res.json({
        success: true,
        user: {
          name: user.name,
          email: user.email,
          phone: user.phone,
        },
        checkInStatus: {
          frequency: user.check_in_frequency,
          nextDue: user.next_check_in_due,
          lastCheckIn: user.last_check_in_date,
          missedCount: user.missed_check_ins,
          lastReminderSent: user.last_reminder_sent,
          finalAlertSent: user.final_alert_sent,
        },
        activeTokens: activeTokens,
      });
    } catch (error) {
      console.error("Get status error:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to get check-in status" });
    }
  }
);

// Get user account data (enhanced with check-in info)
app.get("/api/account/user-data", async (req, res) => {
  try {
    // Get user from session
    const userId = req.session?.userId;

    if (!userId) {
      return res
        .status(401)
        .json({ error: "Not authenticated", success: false });
    }

    // Get user data
    const userData = await db.get(`userId:${userId}`);
    if (!userData) {
      return res.status(404).json({ error: "User not found", success: false });
    }

    // Get all database keys to find related data
    const allKeys = await db.list();

    // Find inner circle contacts for this user
    const innerCircleContacts = [];
    const innerCircleKeys = allKeys.filter((key) =>
      key.startsWith(`inner_circle:${userId}:`)
    );
    for (const key of innerCircleKeys) {
      const contact = await db.get(key);
      if (contact) {
        innerCircleContacts.push(contact);
      }
    }

    // Find important contacts for this user
    const importantContacts = [];
    const importantKeys = allKeys.filter((key) =>
      key.startsWith(`important_contact:${userId}:`)
    );
    for (const key of importantKeys) {
      const contact = await db.get(key);
      if (contact) {
        importantContacts.push(contact);
      }
    }

    // Find co-author if exists
    let coAuthor = null;
    const coAuthorKey = allKeys.find((key) =>
      key.startsWith(`coauthor:${userId}:`)
    );
    if (coAuthorKey) {
      coAuthor = await db.get(coAuthorKey);
    }

    // Get check-in history
    const checkInKeys = allKeys.filter((key) =>
      key.startsWith(`checkin:${userId}:`)
    );
    const checkIns = [];
    for (const key of checkInKeys) {
      const checkIn = await db.get(key);
      if (checkIn) checkIns.push(checkIn);
    }
    checkIns.sort(
      (a, b) => new Date(b.checked_in_at) - new Date(a.checked_in_at)
    );

    console.log(`Loading account data for user ${userData.name}:`, {
      innerCircleCount: innerCircleContacts.length,
      importantContactsCount: importantContacts.length,
      hasCoAuthor: !!coAuthor,
      checkInCount: checkIns.length,
    });

    res.json({
      success: true,
      user: userData,
      innerCircleContacts,
      importantContacts,
      coAuthor,
      checkIns,
    });
  } catch (error) {
    console.error("Error loading account data:", error);
    res
      .status(500)
      .json({ error: "Failed to load account data", success: false });
  }
});

// ===== ACCOUNT MANAGEMENT ENDPOINTS (CRUD) =====

// Update main author (user account details)
app.put("/api/account/update-main-author", async (req, res) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res
        .status(401)
        .json({ success: false, error: "Not authenticated" });
    }

    const { name, phone, email } = req.body;

    if (!name || !phone || !email) {
      return res
        .status(400)
        .json({ success: false, error: "All fields are required" });
    }

    // Get current user data
    const userData = await db.get(`userId:${userId}`);
    if (!userData) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    const oldPhone = userData.phone;
    const oldEmail = userData.email;

    // Update user data
    const updatedUser = {
      ...userData,
      name,
      phone,
      email,
      updated_at: new Date().toISOString(),
    };

    // Update all relevant keys
    await db.set(`userId:${userId}`, updatedUser);
    await db.set(`user:${phone}`, updatedUser);
    await db.set(`email:${email}`, { userId: userId, phone: phone });

    // If phone changed, clean up old phone key
    if (oldPhone !== phone) {
      await db.delete(`user:${oldPhone}`);
    }

    // If email changed, clean up old email key
    if (oldEmail !== email) {
      await db.delete(`email:${oldEmail}`);
    }

    // Update session
    req.session.userPhone = phone;
    req.session.userEmail = email;

    console.log(`✅ Main author updated for user ${userId}`);
    res.json({
      success: true,
      message: "Account details updated successfully",
    });
  } catch (error) {
    console.error("Update main author error:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to update account details" });
  }
});

// Add co-author
app.post("/api/account/add-coauthor", async (req, res) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res
        .status(401)
        .json({ success: false, error: "Not authenticated" });
    }

    const { name, phone, email } = req.body;

    if (!name || !phone || !email) {
      return res
        .status(400)
        .json({ success: false, error: "All fields are required" });
    }

    // Check if co-author already exists
    const allKeys = await db.list();
    const existingCoAuthor = allKeys.find((key) =>
      key.startsWith(`coauthor:${userId}:`)
    );
    if (existingCoAuthor) {
      return res.status(400).json({
        success: false,
        error: "Co-author already exists. Maximum 2 authors allowed.",
      });
    }

    const coAuthorId = uuidv4();
    await db.set(`coauthor:${userId}:${coAuthorId}`, {
      id: coAuthorId,
      user_id: userId,
      name,
      phone,
      email,
      created_at: new Date().toISOString(),
    });

    console.log(`✅ Co-author added for user ${userId}`);
    res.json({ success: true, message: "Co-author added successfully" });
  } catch (error) {
    console.error("Add co-author error:", error);
    res.status(500).json({ success: false, error: "Failed to add co-author" });
  }
});

// Update co-author
app.put("/api/account/update-coauthor", async (req, res) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res
        .status(401)
        .json({ success: false, error: "Not authenticated" });
    }

    const { name, phone, email } = req.body;

    if (!name || !phone || !email) {
      return res
        .status(400)
        .json({ success: false, error: "All fields are required" });
    }

    // Find co-author
    const allKeys = await db.list();
    const coAuthorKey = allKeys.find((key) =>
      key.startsWith(`coauthor:${userId}:`)
    );

    if (!coAuthorKey) {
      return res
        .status(404)
        .json({ success: false, error: "Co-author not found" });
    }

    const existingData = await db.get(coAuthorKey);
    const updatedData = {
      ...existingData,
      name,
      phone,
      email,
      updated_at: new Date().toISOString(),
    };

    await db.set(coAuthorKey, updatedData);
    console.log(`✅ Co-author updated for user ${userId}`);
    res.json({ success: true, message: "Co-author updated successfully" });
  } catch (error) {
    console.error("Update co-author error:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to update co-author" });
  }
});

// Delete co-author
app.delete("/api/account/delete-coauthor", async (req, res) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res
        .status(401)
        .json({ success: false, error: "Not authenticated" });
    }

    // Find co-author key
    const allKeys = await db.list();
    const coAuthorKey = allKeys.find((key) =>
      key.startsWith(`coauthor:${userId}:`)
    );

    if (!coAuthorKey) {
      return res
        .status(404)
        .json({ success: false, error: "Co-author not found" });
    }

    await db.delete(coAuthorKey);
    console.log(`🗑️ Co-author deleted for user ${userId}`);
    res.json({ success: true, message: "Co-author deleted successfully" });
  } catch (error) {
    console.error("Delete co-author error:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to delete co-author" });
  }
});

// Add inner circle contact
app.post("/api/account/add-inner-circle", async (req, res) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res
        .status(401)
        .json({ success: false, error: "Not authenticated" });
    }

    const { name, phone, email, message } = req.body;

    if (!name) {
      return res
        .status(400)
        .json({ success: false, error: "Name is required" });
    }

    const contactId = uuidv4();

    await db.set(`inner_circle:${userId}:${contactId}`, {
      id: contactId,
      user_id: userId,
      name,
      phone: phone || "",
      email: email || "",
      personal_message: message || "",
      created_at: new Date().toISOString(),
    });

    console.log(`✅ Inner circle contact added for user ${userId}`);
    res.json({
      success: true,
      message: "Inner circle contact added",
      contactId,
    });
  } catch (error) {
    console.error("Add inner circle error:", error);
    res.status(500).json({ success: false, error: "Failed to add contact" });
  }
});

// Add important contact
app.post("/api/account/add-important-contact", async (req, res) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res
        .status(401)
        .json({ success: false, error: "Not authenticated" });
    }

    const { type, organization, name, phone, email } = req.body;

    if (!type || !name) {
      return res
        .status(400)
        .json({ success: false, error: "Contact type and name are required" });
    }

    const contactId = uuidv4();

    await db.set(`important_contact:${userId}:${contactId}`, {
      id: contactId,
      user_id: userId,
      contact_type: type,
      name,
      organization: organization || "",
      phone: phone || "",
      email: email || "",
      created_at: new Date().toISOString(),
    });

    console.log(`✅ Important contact added for user ${userId}`);
    res.json({ success: true, message: "Important contact added", contactId });
  } catch (error) {
    console.error("Add important contact error:", error);
    res.status(500).json({ success: false, error: "Failed to add contact" });
  }
});

// Delete contact (generic for any type)
app.delete("/api/account/delete-contact/:type/:contactId", async (req, res) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res
        .status(401)
        .json({ success: false, error: "Not authenticated" });
    }

    const { type, contactId } = req.params;
    const key = `${type}:${userId}:${contactId}`;

    // Check if contact exists
    const existingContact = await db.get(key);
    if (!existingContact) {
      return res
        .status(404)
        .json({ success: false, error: "Contact not found" });
    }

    await db.delete(key);
    console.log(`🗑️ Contact deleted: ${key}`);
    res.json({ success: true, message: "Contact deleted" });
  } catch (error) {
    console.error("Delete contact error:", error);
    res.status(500).json({ success: false, error: "Failed to delete contact" });
  }
});

// Update contact (enhanced with better error handling)
app.put("/api/account/update-contact/:type/:contactId", async (req, res) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res
        .status(401)
        .json({ success: false, error: "Not authenticated" });
    }

    const { type, contactId } = req.params;
    const key = `${type}:${userId}:${contactId}`;

    const existingData = await db.get(key);
    if (!existingData) {
      return res
        .status(404)
        .json({ success: false, error: "Contact not found" });
    }

    // Handle different contact types with proper field mapping
    let updatedData = {
      ...existingData,
      updated_at: new Date().toISOString(),
    };

    if (type === "inner_circle") {
      const { name, phone, email, personal_message } = req.body;

      if (!name) {
        return res
          .status(400)
          .json({ success: false, error: "Name is required" });
      }

      updatedData = {
        ...updatedData,
        name,
        phone: phone || "",
        email: email || "",
        personal_message: personal_message || "",
      };
    } else if (type === "important_contact") {
      const { contact_type, organization, name, phone, email } = req.body;

      if (!contact_type || !name) {
        return res.status(400).json({
          success: false,
          error: "Contact type and name are required",
        });
      }

      updatedData = {
        ...updatedData,
        contact_type,
        organization: organization || "",
        name,
        phone: phone || "",
        email: email || "",
      };
    }

    await db.set(key, updatedData);
    console.log(`✏️ Contact updated: ${key}`);
    res.json({ success: true, message: "Contact updated" });
  } catch (error) {
    console.error("Update contact error:", error);
    res.status(500).json({ success: false, error: "Failed to update contact" });
  }
});

// Protected Admin dashboard (now requires authentication)
app.get("/admin", requireAdminAuth, async (req, res) => {
  try {
    const allData = await db.getAll();

    // Parse users
    const users = [];
    const userKeys = Object.keys(allData).filter((k) =>
      k.startsWith("userId:")
    );

    for (const key of userKeys) {
      const user = allData[key];
      const userId = user.id;

      // Get related data
      const innerCircle = Object.keys(allData)
        .filter((k) => k.startsWith(`inner_circle:${userId}:`))
        .map((k) => allData[k]);

      const importantContacts = Object.keys(allData)
        .filter((k) => k.startsWith(`important_contact:${userId}:`))
        .map((k) => allData[k]);

      const coAuthorKey = Object.keys(allData).find((k) =>
        k.startsWith(`coauthor:${userId}:`)
      );
      const coAuthor = coAuthorKey ? allData[coAuthorKey] : null;

      // Get check-in history
      const checkIns = Object.keys(allData)
        .filter((k) => k.startsWith(`checkin:${userId}:`))
        .map((k) => allData[k]);

      users.push({
        ...user,
        innerCircle,
        importantContacts,
        coAuthor,
        checkIns,
      });
    }

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Admin Dashboard - A Final Message</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }
          .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
          .header h1 { margin: 0; color: #333; display: inline-block; }
          .admin-info { float: right; color: #666; font-size: 14px; }
          .logout-btn { background: #dc3545; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin-left: 10px; }
          .logout-btn:hover { background: #c82333; }
          table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
          th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
          th { background: #007cba; color: white; }
          .user-section { margin: 30px 0; padding: 20px; border: 2px solid #007cba; border-radius: 8px; background: white; }
          h1 { color: #333; }
          h2 { color: #007cba; }
          .stats { display: flex; gap: 30px; margin: 20px 0; }
          .stat-box { padding: 15px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
          .stat-number { font-size: 24px; font-weight: bold; color: #007cba; }
          .security-notice { background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 15px; margin-bottom: 20px; color: #856404; }
          .cancel-btn { background: #dc3545; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; }
          .cancel-btn:hover { background: #c82333; }
          .export-btn { background: #28a745; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; margin-left: 5px; }
          .export-btn:hover { background: #218838; }
          .test-btn { background: #ffc107; color: #000; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; margin-left: 5px; }
          .test-btn:hover { background: #e0a800; }
          .check-in-status { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
          .status-good { background: #d4edda; color: #155724; }
          .status-warning { background: #fff3cd; color: #856404; }
          .status-danger { background: #f8d7da; color: #721c24; }
          .check-in-info { font-size: 11px; color: #666; margin-top: 4px; }
          
          /* Test Panel Styles */
          .test-panel { background: #e8f4ff; border: 2px solid #007cba; border-radius: 8px; padding: 20px; margin: 20px 0; }
          .test-panel h3 { color: #007cba; margin-top: 0; }
          .test-controls { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin: 10px 0; }
          .test-controls button { padding: 8px 15px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
          .test-primary { background: #007cba; color: white; }
          .test-primary:hover { background: #005a8b; }
          .test-warning { background: #ffc107; color: #000; }
          .test-warning:hover { background: #e0a800; }
          .test-danger { background: #dc3545; color: white; }
          .test-danger:hover { background: #c82333; }
          .test-success { background: #28a745; color: white; }
          .test-success:hover { background: #218838; }
          .test-info { background: #17a2b8; color: white; }
          .test-info:hover { background: #138496; }
          .test-status { background: white; padding: 15px; border-radius: 4px; margin: 10px 0; }
          .test-log { background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px; margin: 10px 0; max-height: 200px; overflow-y: auto; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>🔒 Admin Dashboard - A Final Message</h1>
          <div class="admin-info">
            Logged in as: ${req.session.adminUsername} | 
            <button class="logout-btn" onclick="adminLogout()">Logout</button>
          </div>
          <div style="clear: both;"></div>
        </div>

        <div class="security-notice">
          <strong>🛡️ Secure Admin Area:</strong> You have administrative access to manage user accounts and system settings.
          <br><strong>🧪 TEST MODE:</strong> Check-in testing controls are enabled below.
        </div>
        
        <div class="stats">
          <div class="stat-box">
            <div class="stat-number">${users.length}</div>
            <div>Total Users</div>
          </div>
          <div class="stat-box">
            <div class="stat-number">${
              users.filter((u) => u.subscription_status === "active").length
            }</div>
            <div>Active Subscriptions</div>
          </div>
          <div class="stat-box">
            <div class="stat-number">${
              users.filter((u) => u.missed_check_ins > 0).length
            }</div>
            <div>Users with Missed Check-ins</div>
          </div>
          <div class="stat-box">
            <div class="stat-number">${users.reduce(
              (sum, u) => sum + (u.checkIns?.length || 0),
              0
            )}</div>
            <div>Total Check-ins</div>
          </div>
        </div>
        
        <!-- Check-in Test Panel -->
        <div class="test-panel">
          <h3>🧪 Check-in System Test Controls</h3>
          <p>Test the check-in system without waiting for actual dates. Select a user below to test their check-in flow.</p>
          
          <div class="test-controls">
            <select id="testUserSelect" onchange="loadTestStatus()">
              <option value="">Select a user to test...</option>
              ${users
                .map(
                  (u) =>
                    `<option value="${u.id}">${u.name} (${u.phone})</option>`
                )
                .join("")}
            </select>
          </div>
          
          <div id="testStatusPanel" style="display: none;">
            <div class="test-status">
              <h4>Current Status for <span id="testUserName"></span></h4>
              <div id="testStatusInfo"></div>
            </div>
            
            <div class="test-controls">
              <button class="test-primary" onclick="testSendCheckIn(1)">📧 Send Check-in (Attempt 1)</button>
              <button class="test-warning" onclick="testSendCheckIn(2)">📧 Send Check-in (Attempt 2)</button>
              <button class="test-danger" onclick="testSendCheckIn(3)">📧 Send Check-in (Attempt 3)</button>
              <button class="test-danger" onclick="testSendFinalAlert()">🚨 Send Final Alert</button>
            </div>
            
            <div class="test-controls">
              <button class="test-info" onclick="testSimulateMissed(1)">⏭️ Simulate 1 Missed</button>
              <button class="test-info" onclick="testSimulateMissed(2)">⏭️ Simulate 2 Missed</button>
              <button class="test-info" onclick="testSimulateMissed(3)">⏭️ Simulate 3 Missed</button>
              <button class="test-success" onclick="testResetStatus()">🔄 Reset Status</button>
            </div>
            
            <div class="test-log" id="testLog">
              <strong>Test Log:</strong><br>
              Select an action above to see results here...
            </div>
          </div>
        </div>
        
        <h2>User Management</h2>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Phone</th>
              <th>Email</th>
              <th>Created</th>
              <th>Check-in Status</th>
              <th>Next Check-in</th>
              <th>Subscription</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${users
              .map((user) => {
                const nextCheckIn = user.next_check_in_due
                  ? new Date(user.next_check_in_due).toLocaleDateString()
                  : "Not set";
                const frequency = user.check_in_frequency
                  ? `${user.check_in_frequency} months`
                  : "Not set";
                const isActive = user.subscription_status === "active";
                const statusClass = isActive ? "status-good" : "status-danger";
                const statusText = isActive
                  ? "Active"
                  : user.subscription_status || "Inactive";

                let checkInStatus = "";
                let checkInClass = "status-good";
                if (user.missed_check_ins === 0) {
                  checkInStatus = "✅ On Track";
                } else if (user.missed_check_ins === 1) {
                  checkInStatus = "⚠️ 1 Missed";
                  checkInClass = "status-warning";
                } else if (user.missed_check_ins === 2) {
                  checkInStatus = "⚠️ 2 Missed";
                  checkInClass = "status-warning";
                } else if (user.missed_check_ins >= 3) {
                  checkInStatus = "🚨 3+ Missed";
                  checkInClass = "status-danger";
                }

                return `
                  <tr>
                    <td>${user.name}</td>
                    <td>${user.phone}</td>
                    <td>${user.email}</td>
                    <td>${new Date(user.created_at).toLocaleDateString()}</td>
                    <td>
                      <span class="check-in-status ${checkInClass}">${checkInStatus}</span>
                      <div class="check-in-info">Every ${frequency}</div>
                    </td>
                    <td>${nextCheckIn}</td>
                    <td><span class="check-in-status ${statusClass}">${statusText}</span></td>
                    <td>
                      <button class="cancel-btn" onclick="cancelAccount('${
                        user.id
                      }', '${user.name}')">
                        Cancel
                      </button>
                      <button class="export-btn" onclick="exportUserData('${
                        user.id
                      }', '${user.name}')">
                        Export
                      </button>
                      <button class="test-btn" onclick="selectUserForTest('${
                        user.id
                      }')">
                        Test
                      </button>
                    </td>
                  </tr>
                `;
              })
              .join("")}
          </tbody>
        </table>
        
        <h2>Detailed User Information</h2>
        ${users
          .map(
            (user) => `
          <div class="user-section">
            <h2>${user.name} (ID: ${user.id.slice(0, 8)}...)</h2>
            <p><strong>Phone:</strong> ${user.phone}</p>
            <p><strong>Email:</strong> ${user.email}</p>
            <p><strong>Stripe Customer:</strong> ${
              user.stripe_customer_id || "Demo Mode"
            }</p>
            <p><strong>Stripe Subscription:</strong> ${
              user.stripe_subscription_id || "Demo Mode"
            }</p>
            <p><strong>Check-in Frequency:</strong> ${
              user.check_in_frequency
                ? user.check_in_frequency + " months"
                : "Not set"
            }</p>
            <p><strong>Subscription Start:</strong> ${
              user.subscription_start_date
                ? new Date(user.subscription_start_date).toLocaleDateString()
                : "Not set"
            }</p>
            <p><strong>Next Check-in Due:</strong> ${
              user.next_check_in_due
                ? new Date(user.next_check_in_due).toLocaleDateString()
                : "Not set"
            }</p>
            <p><strong>Last Check-in:</strong> ${
              user.last_check_in_date
                ? new Date(user.last_check_in_date).toLocaleDateString()
                : "Never"
            }</p>
            <p><strong>Missed Check-ins:</strong> ${
              user.missed_check_ins || 0
            }/3</p>
            ${
              user.final_alert_sent
                ? `<p style="color: red;"><strong>⚠️ Final Alert Sent:</strong> ${new Date(
                    user.final_alert_sent
                  ).toLocaleDateString()}</p>`
                : ""
            }
            
            ${
              user.checkIns && user.checkIns.length > 0
                ? `
              <h3>Recent Check-ins (${user.checkIns.length} total)</h3>
              <ul>
                ${user.checkIns
                  .slice(0, 5)
                  .map(
                    (c) => `
                  <li>${new Date(c.checked_in_at).toLocaleString()} - ${
                      c.method === "manual"
                        ? "Manual Check-in"
                        : "Link Check-in"
                    }</li>
                `
                  )
                  .join("")}
              </ul>
            `
                : "<p><em>No check-ins yet</em></p>"
            }
            
            ${
              user.coAuthor
                ? `
              <h3>Co-Author</h3>
              <p>${user.coAuthor.name} - ${user.coAuthor.phone} - ${user.coAuthor.email}</p>
            `
                : ""
            }
            
            ${
              user.innerCircle.length > 0
                ? `
              <h3>Inner Circle Contacts (${user.innerCircle.length})</h3>
              <ul>
                ${user.innerCircle
                  .map(
                    (c) => `
                  <li><strong>${c.name}</strong> - ${c.phone || "No phone"} - ${
                      c.email || "No email"
                    }
                    ${
                      c.personal_message
                        ? `<br><em>Personal Message: "${c.personal_message}"</em>`
                        : ""
                    }
                  </li>
                `
                  )
                  .join("")}
              </ul>
            `
                : "<p><em>No inner circle contacts</em></p>"
            }
            
            ${
              user.importantContacts.length > 0
                ? `
              <h3>Important Contacts (${user.importantContacts.length})</h3>
              <ul>
                ${user.importantContacts
                  .map(
                    (c) => `
                  <li><strong>${c.contact_type}:</strong> ${c.name} 
                    ${c.organization ? `(${c.organization})` : ""}
                    - ${c.phone || "No phone"} - ${c.email || "No email"}
                  </li>
                `
                  )
                  .join("")}
              </ul>
            `
                : "<p><em>No important contacts</em></p>"
            }
          </div>
        `
          )
          .join("")}

        <script>
          let selectedTestUser = null;
          
          async function adminLogout() {
            try {
              const response = await fetch('/api/admin/logout', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
              });
              
              const data = await response.json();
              
              if (data.success) {
                window.location.href = '/admin-login';
              } else {
                alert('Logout failed');
              }
            } catch (error) {
              console.error('Logout error:', error);
              alert('Logout failed');
            }
          }

          async function cancelAccount(userId, userName) {
            if (confirm(\`Are you sure you want to cancel the account for \${userName}? This will cancel their Stripe subscription and deactivate their account.\`)) {
              try {
                const response = await fetch(\`/api/admin/cancel-account/\${userId}\`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' }
                });
                
                const data = await response.json();
                
                if (data.success) {
                  alert('Account cancelled successfully');
                  location.reload();
                } else {
                  alert('Failed to cancel account: ' + (data.error || 'Unknown error'));
                }
              } catch (error) {
                console.error('Cancel account error:', error);
                alert('Failed to cancel account');
              }
            }
          }

          async function exportUserData(userId, userName) {
            try {
              const response = await fetch(\`/api/admin/export-user-data/\${userId}\`, {
                method: 'GET'
              });
              
              if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = \`\${userName.replace(/\\s+/g, '_')}_InnerCircle_Data.pdf\`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                alert('Export completed successfully!');
              } else {
                const data = await response.json();
                alert('Export failed: ' + (data.error || 'Unknown error'));
              }
            } catch (error) {
              console.error('Export error:', error);
              alert('Export failed');
            }
          }
          
          // Test Functions
          function selectUserForTest(userId) {
            document.getElementById('testUserSelect').value = userId;
            loadTestStatus();
          }
          
          async function loadTestStatus() {
            const userId = document.getElementById('testUserSelect').value;
            if (!userId) {
              document.getElementById('testStatusPanel').style.display = 'none';
              return;
            }
            
            selectedTestUser = userId;
            
            try {
              const response = await fetch(\`/api/admin/test/checkin-status/\${userId}\`);
              const data = await response.json();
              
              if (data.success) {
                document.getElementById('testUserName').textContent = data.user.name;
                document.getElementById('testStatusInfo').innerHTML = \`
                  <p><strong>Email:</strong> \${data.user.email}<br>
                  <strong>Phone:</strong> \${data.user.phone}<br>
                  <strong>Frequency:</strong> Every \${data.checkInStatus.frequency} months<br>
                  <strong>Next Due:</strong> \${new Date(data.checkInStatus.nextDue).toLocaleDateString()}<br>
                  <strong>Last Check-in:</strong> \${data.checkInStatus.lastCheckIn ? new Date(data.checkInStatus.lastCheckIn).toLocaleDateString() : 'Never'}<br>
                  <strong>Missed Count:</strong> \${data.checkInStatus.missedCount}/3<br>
                  <strong>Active Tokens:</strong> \${data.activeTokens.length}</p>
                \`;
                document.getElementById('testStatusPanel').style.display = 'block';
                logTest('Status loaded for ' + data.user.name);
              }
            } catch (error) {
              console.error('Load status error:', error);
              alert('Failed to load status');
            }
          }
          
          async function testSendCheckIn(attemptNumber) {
            if (!selectedTestUser) return;
            
            try {
              const response = await fetch(\`/api/admin/test/trigger-checkin/\${selectedTestUser}\`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ attemptNumber })
              });
              
              const data = await response.json();
              
              if (data.success) {
                logTest(\`✅ \${data.message}\\n📧 Check console.log for SMS/Email content\\n📱 Phone: \${data.phone}\\n📧 Email: \${data.email}\`);
                alert('Check-in reminder sent! Check the server console for the message content and check-in link.');
                loadTestStatus();
              } else {
                logTest('❌ Failed: ' + data.error);
              }
            } catch (error) {
              console.error('Test error:', error);
              logTest('❌ Error: ' + error.message);
            }
          }
          
          async function testSimulateMissed(count) {
            if (!selectedTestUser) return;
            
            try {
              const response = await fetch(\`/api/admin/test/simulate-missed/\${selectedTestUser}\`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ count })
              });
              
              const data = await response.json();
              
              if (data.success) {
                logTest(\`✅ \${data.message}\\n➡️ \${data.nextAction}\`);
                loadTestStatus();
              } else {
                logTest('❌ Failed: ' + data.error);
              }
            } catch (error) {
              console.error('Test error:', error);
              logTest('❌ Error: ' + error.message);
            }
          }
          
          async function testSendFinalAlert() {
            if (!selectedTestUser) return;
            
            try {
              const response = await fetch(\`/api/admin/test/send-final-alert/\${selectedTestUser}\`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
              });
              
              const data = await response.json();
              
              if (data.success) {
                logTest(\`🚨 \${data.message}\\n📧 Check console.log for final alert email content to care@afinalmessage.com\`);
                alert('Final alert sent! Check the server console for the email content that would be sent to care@afinalmessage.com');
                loadTestStatus();
              } else {
                logTest('❌ Failed: ' + data.error);
              }
            } catch (error) {
              console.error('Test error:', error);
              logTest('❌ Error: ' + error.message);
            }
          }
          
          async function testResetStatus() {
            if (!selectedTestUser) return;
            
            try {
              const response = await fetch(\`/api/admin/test/reset-checkin/\${selectedTestUser}\`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
              });
              
              const data = await response.json();
              
              if (data.success) {
                logTest(\`✅ \${data.message}\\n📅 Next check-in: \${new Date(data.nextCheckIn).toLocaleDateString()}\`);
                loadTestStatus();
              } else {
                logTest('❌ Failed: ' + data.error);
              }
            } catch (error) {
              console.error('Test error:', error);
              logTest('❌ Error: ' + error.message);
            }
          }
          
          function logTest(message) {
            const log = document.getElementById('testLog');
            const timestamp = new Date().toLocaleTimeString();
            log.innerHTML += \`<br>[\${timestamp}] \${message}\`;
            log.scrollTop = log.scrollHeight;
          }
        </script>
      </body>
      </html>
    `);
  } catch (error) {
    console.error("Admin error:", error);
    res.status(500).send("Admin panel error");
  }
});

// Debug endpoint to see database contents
app.get("/api/debug", async (req, res) => {
  try {
    const allData = await db.getAll();
    res.json({
      totalKeys: Object.keys(allData).length,
      data: allData,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Test endpoint
app.get("/api/test", (req, res) => {
  res.json({
    message: "API is working",
    timestamp: new Date().toISOString(),
  });
});

// Catch-all 404 handler - MUST BE LAST
app.use((req, res) => {
  console.log("404 - Route not found:", req.method, req.path);
  res.status(404).send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>404 - Page Not Found</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 100px auto; text-align: center; }
            h1 { color: #333; }
            a { color: #007cba; text-decoration: none; }
        </style>
    </head>
    <body>
        <h1>404 - Page Not Found</h1>
        <p>The page you're looking for doesn't exist.</p>
        <p><a href="/">Go to Homepage</a></p>
    </body>
    </html>
  `);
});

// Start server and initialize existing users
app.listen(port, () => {
  console.log(`🚀 A Final Message server running on port ${port}`);
  console.log(`📱 DEMO MODE: Check console logs for verification codes`);
  console.log(`🌐 Visit your app URL to test the homepage`);
  console.log(`🔍 Enhanced login endpoints ready with two-step verification`);
  console.log(`👨‍💼 Protected admin panel available at /admin`);
  console.log(`🔑 Admin login available at /admin-login`);
  console.log(`🛠 Debug endpoint at /api/debug`);
  console.log(`✅ Test endpoint at /api/test`);
  console.log(`📂 Database will be saved to database.json`);
  console.log(`✨ CRUD operations enabled for contacts`);
  console.log(`📧 Enhanced edit functionality ready`);
  console.log(`🚀 Admin authentication system active`);
  console.log(`⏰ Check-in system with cron jobs active`);
  console.log(`📅 Daily check-in verification runs at midnight PST`);
  console.log(`📄 PDF export functionality ready`);
  console.log(`🧪 TEST MODE: Check-in testing endpoints available`);

  // Initialize existing users with check-in fields
  initializeExistingUsers();
});

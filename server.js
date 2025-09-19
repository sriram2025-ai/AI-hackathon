const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const axios = require('axios');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Database Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/medimind', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// User Schema
const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['physician', 'nurse', 'administrator', 'staff'],
    default: 'staff'
  },
  organization: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', UserSchema);

// Patient Schema
const PatientSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  dateOfBirth: {
    type: Date,
    required: true
  },
  gender: {
    type: String,
    enum: ['Male', 'Female', 'Other'],
    required: true
  },
  contactInfo: {
    phone: String,
    email: String,
    address: String
  },
  medicalHistory: [{
    condition: String,
    diagnosedDate: Date,
    notes: String
  }],
  medications: [{
    name: String,
    dosage: String,
    frequency: String,
    startDate: Date,
    endDate: Date
  }],
  allergies: [String],
  visits: [{
    date: Date,
    reason: String,
    diagnosis: String,
    treatment: String,
    notes: String,
    doctor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Patient = mongoose.model('Patient', PatientSchema);

// Auth Middleware
const auth = (req, res, next) => {
  const token = req.header('x-auth-token');
  
  if (!token) {
    return res.status(401).json({ msg: 'No token, authorization denied' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role, organization } = req.body;
  
  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ msg: 'User already exists' });
    }
    
    user = new User({
      name,
      email,
      password,
      role,
      organization
    });
    
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    
    await user.save();
    
    const payload = {
      user: {
        id: user.id
      }
    };
    
    jwt.sign(
      payload,
      process.env.JWT_SECRET || 'your_jwt_secret_key',
      { expiresIn: '5h' },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }
    
    const payload = {
      user: {
        id: user.id
      }
    };
    
    jwt.sign(
      payload,
      process.env.JWT_SECRET || 'your_jwt_secret_key',
      { expiresIn: '5h' },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Patient Routes
app.get('/api/patients', auth, async (req, res) => {
  try {
    const patients = await Patient.find();
    res.json(patients);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.get('/api/patients/:id', auth, async (req, res) => {
  try {
    const patient = await Patient.findById(req.params.id);
    if (!patient) {
      return res.status(404).json({ msg: 'Patient not found' });
    }
    res.json(patient);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.post('/api/patients', auth, async (req, res) => {
  const {
    name,
    dateOfBirth,
    gender,
    contactInfo,
    medicalHistory,
    medications,
    allergies
  } = req.body;
  
  try {
    const newPatient = new Patient({
      name,
      dateOfBirth,
      gender,
      contactInfo,
      medicalHistory,
      medications,
      allergies
    });
    
    const patient = await newPatient.save();
    res.json(patient);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.put('/api/patients/:id', auth, async (req, res) => {
  const {
    name,
    dateOfBirth,
    gender,
    contactInfo,
    medicalHistory,
    medications,
    allergies
  } = req.body;
  
  const patientFields = {};
  if (name) patientFields.name = name;
  if (dateOfBirth) patientFields.dateOfBirth = dateOfBirth;
  if (gender) patientFields.gender = gender;
  if (contactInfo) patientFields.contactInfo = contactInfo;
  if (medicalHistory) patientFields.medicalHistory = medicalHistory;
  if (medications) patientFields.medications = medications;
  if (allergies) patientFields.allergies = allergies;
  
  try {
    let patient = await Patient.findById(req.params.id);
    if (!patient) {
      return res.status(404).json({ msg: 'Patient not found' });
    }
    
    patient = await Patient.findByIdAndUpdate(
      req.params.id,
      { $set: patientFields },
      { new: true }
    );
    
    res.json(patient);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.post('/api/patients/:id/visits', auth, async (req, res) => {
  const { date, reason, diagnosis, treatment, notes } = req.body;
  
  try {
    const patient = await Patient.findById(req.params.id);
    if (!patient) {
      return res.status(404).json({ msg: 'Patient not found' });
    }
    
    patient.visits.push({
      date,
      reason,
      diagnosis,
      treatment,
      notes,
      doctor: req.user.id
    });
    
    await patient.save();
    res.json(patient.visits);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// AI Routes
app.get('/api/ai/summary/:patientId', auth, async (req, res) => {
  try {
    const patient = await Patient.findById(req.params.patientId);
    if (!patient) {
      return res.status(404).json({ msg: 'Patient not found' });
    }
    
    let summary = `Patient: ${patient.name}, ${patient.gender}, born ${patient.dateOfBirth.getFullYear()}.\n\n`;
    
    if (patient.medicalHistory.length > 0) {
      summary += "Medical History:\n";
      patient.medicalHistory.forEach(condition => {
        summary += `- ${condition.condition} (diagnosed ${condition.diagnosedDate.getFullYear()}): ${condition.notes}\n`;
      });
    }
    
    if (patient.medications.length > 0) {
      summary += "\nCurrent Medications:\n";
      patient.medications.forEach(med => {
        summary += `- ${med.name} ${med.dosage}, ${med.frequency}\n`;
      });
    }
    
    if (patient.allergies.length > 0) {
      summary += `\nAllergies: ${patient.allergies.join(', ')}\n`;
    }
    
    if (patient.visits.length > 0) {
      const lastVisit = patient.visits[patient.visits.length - 1];
      summary += `\nLast Visit: ${lastVisit.date.toDateString()}\n`;
      summary += `Reason: ${lastVisit.reason}\n`;
      summary += `Diagnosis: ${lastVisit.diagnosis}\n`;
      summary += `Treatment: ${lastVisit.treatment}\n`;
    }
    
    // AI insights
    summary += "\nAI Insights:\n";
    
    // Check for potential issues
    if (patient.medications.some(med => med.name.toLowerCase().includes('metformin'))) {
      summary += "- Patient is on Metformin. Monitor renal function periodically.\n";
    }
    
    if (patient.medications.some(med => med.name.toLowerCase().includes('lisinopril'))) {
      summary += "- Patient is on Lisinopril. Monitor potassium levels.\n";
    }
    
    if (patient.medicalHistory.some(hist => hist.condition.toLowerCase().includes('diabetes'))) {
      summary += "- Patient has diabetes. Recommend HbA1c test every 3-6 months.\n";
    }
    
    if (patient.medicalHistory.some(hist => hist.condition.toLowerCase().includes('hypertension'))) {
      summary += "- Patient has hypertension. Monitor blood pressure regularly.\n";
    }
    
    res.json({ summary });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.post('/api/ai/search', auth, async (req, res) => {
  const { query } = req.body;
  
  try {
    const patients = await Patient.find({
      $or: [
        { name: { $regex: query, $options: 'i' } },
        { 'medicalHistory.condition': { $regex: query, $options: 'i' } },
        { 'medications.name': { $regex: query, $options: 'i' } },
        { allergies: { $regex: query, $options: 'i' } },
        { 'visits.diagnosis': { $regex: query, $options: 'i' } }
      ]
    });
    
    res.json(patients);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.post('/api/ai/decision-support', auth, async (req, res) => {
  const { patientId, medication, condition } = req.body;
  
  try {
    const patient = await Patient.findById(patientId);
    if (!patient) {
      return res.status(404).json({ msg: 'Patient not found' });
    }
    
    const alerts = [];
    
    // Check for allergies
    if (patient.allergies.some(allergy => 
        medication.toLowerCase().includes(allergy.toLowerCase()))) {
      alerts.push({
        type: 'allergy',
        severity: 'high',
        message: `Patient has allergy to ${medication}`
      });
    }
    
    // Check for drug interactions
    if (medication.toLowerCase().includes('warfarin')) {
      if (patient.medications.some(med => 
          med.name.toLowerCase().includes('ibuprofen') || 
          med.name.toLowerCase().includes('aspirin'))) {
        alerts.push({
          type: 'interaction',
          severity: 'high',
          message: 'Warfarin interacts with NSAIDs increasing bleeding risk'
        });
      }
    }
    
    // Check for condition-specific risks
    if (condition && condition.toLowerCase().includes('diabetes')) {
      if (patient.medications.some(med => 
          med.name.toLowerCase().includes('prednisone'))) {
        alerts.push({
          type: 'risk',
          severity: 'medium',
          message: 'Corticosteroids may increase blood glucose levels in diabetic patients'
        });
      }
    }
    
    // Add general recommendations
    const recommendations = [];
    
    if (patient.medicalHistory.some(hist => hist.condition.toLowerCase().includes('hypertension'))) {
      recommendations.push("Monitor blood pressure regularly");
    }
    
    if (patient.medicalHistory.some(hist => hist.condition.toLowerCase().includes('diabetes'))) {
      recommendations.push("Monitor HbA1c levels every 3-6 months");
    }
    
    if (patient.age > 65) {
      recommendations.push("Consider renal function monitoring for medications");
    }
    
    res.json({
      alerts,
      recommendations
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Voice Routes
app.post('/api/voice/transcribe', auth, (req, res) => {
  const { audioBase64 } = req.body;
  
  if (!audioBase64) {
    return res.status(400).json({ msg: 'No audio data provided' });
  }
  
  // Create uploads directory if it doesn't exist
  const uploadsDir = path.join(__dirname, 'uploads');
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
  }
  
  const audioPath = path.join(uploadsDir, 'audio.wav');
  const audioBuffer = Buffer.from(audioBase64, 'base64');
  fs.writeFileSync(audioPath, audioBuffer);
  
  // Mock transcription
  setTimeout(() => {
    const transcription = "Patient presents with chest pain and shortness of breath. " +
                         "Vital signs: BP 140/90, HR 85, RR 18, Temp 98.6°F. " +
                         "Patient reports pain started yesterday and has been gradually worsening. " +
                         "No history of cardiac issues. Recommending ECG and cardiac enzymes.";
    
    // Clean up the file
    fs.unlinkSync(audioPath);
    
    res.json({ transcription });
  }, 1000);
});

// Interoperability Routes
app.get('/api/interoperability/labs/:patientId', auth, async (req, res) => {
  try {
    // Mock lab results
    const mockLabResults = [
      {
        test: 'Complete Blood Count',
        date: '2023-05-15',
        results: {
          'WBC': '7.2 x 10^9/L',
          'RBC': '4.8 x 10^12/L',
          'Hemoglobin': '14.5 g/dL',
          'Hematocrit': '43%',
          'Platelets': '250 x 10^9/L'
        },
        status: 'Normal'
      },
      {
        test: 'Comprehensive Metabolic Panel',
        date: '2023-05-15',
        results: {
          'Glucose': '95 mg/dL',
          'BUN': '15 mg/dL',
          'Creatinine': '0.9 mg/dL',
          'Sodium': '140 mmol/L',
          'Potassium': '4.2 mmol/L',
          'Chloride': '102 mmol/L',
          'CO2': '26 mmol/L'
        },
        status: 'Normal'
      }
    ];
    
    res.json(mockLabResults);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.post('/api/interoperability/pharmacy/prescribe', auth, async (req, res) => {
  try {
    const { patientId, medication, dosage, instructions } = req.body;
    
    // Mock prescription ID
    const prescriptionId = `RX${Math.floor(100000000 + Math.random() * 900000000)}`;
    
    res.json({
      success: true,
      prescriptionId,
      message: 'Prescription sent to pharmacy successfully'
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.get('/api/interoperability/hospitals/:patientId/records', auth, async (req, res) => {
  try {
    // Mock hospital records
    const mockHospitalRecords = [
      {
        hospital: 'City General Hospital',
        admissionDate: '2023-01-10',
        dischargeDate: '2023-01-15',
        diagnosis: 'Community-acquired pneumonia',
        treatment: 'Antibiotics, oxygen therapy',
        notes: 'Patient responded well to treatment. Discharged in stable condition.'
      }
    ];
    
    res.json(mockHospitalRecords);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Chatbot Routes
app.post('/api/chatbot/message', (req, res) => {
  const { message } = req.body;
  
  if (!message) {
    return res.status(400).json({ msg: 'No message provided' });
  }
  
  // Simple response logic based on keywords
  let response = '';
  const lowerMessage = message.toLowerCase();
  
  if (lowerMessage.includes('how does it work') || lowerMessage.includes('how it works')) {
    response = "MediMind AI uses advanced machine learning algorithms to analyze patient data, identify trends, and provide actionable insights. It integrates seamlessly with your existing workflow and continuously learns from each interaction to improve its recommendations.";
  } else if (lowerMessage.includes('pricing') || lowerMessage.includes('cost')) {
    response = "We offer flexible pricing plans tailored to practices of all sizes. Our basic plan starts at $99 per month per provider, with enterprise solutions available for larger organizations. Would you like me to connect you with our sales team for a custom quote?";
  } else if (lowerMessage.includes('security') || lowerMessage.includes('hipaa')) {
    response = "Security is our top priority. MediMind AI is HIPAA compliant, uses end-to-end encryption for all data, and undergoes regular security audits. We also provide role-based access controls and detailed audit logs to ensure patient data is always protected.";
  } else if (lowerMessage.includes('ai summaries') || lowerMessage.includes('clinical notes')) {
    response = "Our AI Summaries feature automatically generates comprehensive clinical notes from patient data, saving time and ensuring accuracy in documentation. It reduces documentation time by up to 70% while maintaining accuracy and compliance.";
  } else if (lowerMessage.includes('smart search')) {
    response = "Smart Search allows you to instantly find patient information, records, and notes with our powerful search functionality. It understands medical terminology and context, eliminating the need to navigate through multiple screens.";
  } else if (lowerMessage.includes('decision support')) {
    response = "Our Decision Support system provides intelligent alerts about potential risks, drug interactions, and treatment recommendations based on the latest medical research. It helps catch potential issues that might be missed in manual reviews.";
  } else if (lowerMessage.includes('voice') || lowerMessage.includes('dictate')) {
    response = "Our Voice-to-Text feature allows doctors to dictate notes hands-free with 99% accuracy for medical terminology. This enables you to maintain eye contact and build better patient relationships while documenting.";
  } else if (lowerMessage.includes('interoperability') || lowerMessage.includes('connect')) {
    response = "MediMind AI seamlessly connects with labs, pharmacies, and hospitals through HL7, FHIR, and API integrations. This ensures you have complete patient information regardless of where care was provided.";
  } else if (lowerMessage.includes('request demo') || lowerMessage.includes('demo')) {
    response = "I'd be happy to help you request a demo! Please visit our website and click on the 'Request Demo' button, or I can connect you with our sales team directly.";
  } else if (lowerMessage.includes('features')) {
    response = "MediMind AI offers several key features: AI Summaries for auto-generating clinical notes, Smart Search for instant information access, Decision Support for risk alerts, Voice-to-Text for dictation, and Interoperability to connect with external systems. Would you like more details about any specific feature?";
  } else {
    response = "I'm not sure I understand. Could you please rephrase your question? You can ask me about how MediMind AI works, pricing, security features, or any of our features like AI Summaries, Smart Search, Decision Support, Voice-to-Text, or Interoperability.";
  }
  
  res.json({ response });
});

// Serve static files in production
if (process.env.NODE_ENV === 'production') {
  // Set static folder
  app.use(express.static(path.join(__dirname, '../frontend')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.resolve(__dirname, '../frontend', 'index.html'));
  });
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
const mongoose = require("mongoose");

const allowedTypes = [
    "phishing",
    "malware",
    "unauthorized",
    "data_breach",
    "suspicious",
    "Phishing",
    "Phishing Attack",
    "Malware Infection",
    "Unauthorized Access",
    "Data Breach",
    "Suspicious Activity"
];

const incidentSchema = new mongoose.Schema({

    incidentId: {
        type: String,
        unique: true
    },

    type: {
        type: String,
        required: true,
        trim: true,
        enum: allowedTypes
    },

    description: {
        type: String,
        required: true
    },

    severity: {
        type: String,
        enum: ["Low", "Medium", "High", "Critical"],
        required: true
    },

    status: {
        type: String,
        enum: ["Pending", "Investigating", "Resolved"],
        default: "Pending"
    },

    investigationNotes: {
        type: String,
        default: ""
    },

    reportedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        default: null
    },

    date: {
        type: Date,
        default: Date.now
    }

}, { timestamps: true });

incidentSchema.index({ reportedBy: 1, createdAt: -1 });
incidentSchema.index({ status: 1, severity: 1 });

module.exports = mongoose.model("Incident", incidentSchema);
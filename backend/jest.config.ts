module.exports = {
  "testEnvironment": "node",
  "setupFilesAfterEnv": [
    "<jest-env>"
  ],
  "testMatch": [
    "**/__tests__/**/*.js",
    "**/?(*.)+(spec|test).js"
  ],
  "coverageDirectory": "coverage",
  "coverageReporters": [
    "json",
    "text",
    "lcov"
  ],
  "coverageThreshold": {
    "global": {
      "branches": 80,
      "functions": 80,
      "lines": 80,
      "statements": 80
    }
  },
  "preset": "ts-jest"
};
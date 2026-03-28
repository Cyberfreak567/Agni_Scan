import React from "react";
import ReactDOM from "react-dom/client";
import { AuthForm } from "./components/AuthForm";
import { Dashboard } from "./components/Dashboard";
import { getSession } from "./lib/api";
import "./styles.css";

function App() {
  const session = getSession();
  return session.token ? <Dashboard /> : <AuthForm onAuthenticated={() => window.location.reload()} />;
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

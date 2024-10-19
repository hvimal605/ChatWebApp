import React, { createContext, useContext, useState, useEffect } from "react";
import Cookies from "js-cookie";

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  let initialUserState;

  try {
    // Attempt to parse the cookie
    initialUserState = Cookies.get("harshcookie")
      ? JSON.parse(Cookies.get("harshcookie"))
      : localStorage.getItem("Chatapp")
      ? JSON.parse(localStorage.getItem("Chatapp"))
      : undefined;
  } catch (error) {
    console.error("Failed to parse cookie:", error);
    // Fallback to localStorage if cookie is not valid JSON
    initialUserState = localStorage.getItem("Chatapp")
      ? JSON.parse(localStorage.getItem("Chatapp"))
      : undefined;
  }

  const [authUser, setAuthUser] = useState(initialUserState);

  useEffect(() => {
    if (authUser) {
      // Save user state in both cookie and localStorage
      Cookies.set("harshcookie", JSON.stringify(authUser), { expires: 7 });
      localStorage.setItem("Chatapp", JSON.stringify(authUser));
    } else {
      // Remove cookie and localStorage if user state is cleared
      Cookies.remove("harshcookie");
      localStorage.removeItem("Chatapp");
    }
  }, [authUser]);

  return (
    <AuthContext.Provider value={[authUser, setAuthUser]}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);

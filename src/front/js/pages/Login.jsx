import React, { useContext, useEffect, useState } from "react";
import { Context } from "../store/appContext";
import { Navigate } from "react-router-dom";



export const Login = () => {
    const { store, actions } = useContext(Context);
    const [ email, setEmail ] = useState("");
    const [ password, setPassword ] = useState("");
    
    // setEmailLogin("test");
    // setPasswordLogin("pass");


    const handleOnClick = async () => {
        const url = process.env.BACKEND_URL + "/api/login";
        console.log(url);
        const options = {
            method : "POST",
            body : JSON.stringify({email, password}),
            headers : {
                "Content-Type" : "application/json"
            }
        };
        console.log(options);

        const response = await fetch(url, options);
        console.log(response);
        if(response.ok){
            const data = await response.json();
            actions.login(data.token)
            // localStorage.setItem("token", data.token);
            console.log(data);
        }else{
            const msg = document.querySelector("#errorMessage");
            msg.style.display = "block";
            setTimeout(() => {
                msg.style.display = "none";
            }, 3000)
            console.log(" Falló...", response.status, response.statusText)
        }


    }


    // useEffect(() => {
    //     console.log(emailLogin)
    //     console.log(passwordLogin)
    // }, [emailLogin, passwordLogin])


    return (
        store.isLoggedIn ? <Navigate to="/dashboard"/>:
        <div>

            <div className="col-md-6 py-5 px-md-5">
                <h1 className="text-center">THIS IS LOGÍN</h1>
                <p id="errorMessage" className="p-3" style={{color: "red", borderRadius: "10px", border: "solid red 3px", display: "none"}}>The pass or user doesn't exists <a href="/register">Would you like to sign up?</a></p>
                <div className="form-outline mb-4">
                    <input type="email" id="form2Example1" className="form-control" 
                        value={email} onChange={(e) => setEmail(e.target.value)}/>
                    <label className="form-label" htmlFor="form2Example1">Email address</label>
                </div>
                <div className="form-outline mb-4">
                    <input type="password" id="form2Example2" className="form-control"
                        value={password} onChange={(e) => setPassword(e.target.value)}/>
                    <label className="form-label" htmlFor="form2Example2">Password</label>
                </div>
                <div>
                    <button onClick={handleOnClick} type="button" className="btn btn-primary btn-block mb-4">
                        Sign in
                    </button>
                </div>
            </div>


        </div>

    )


}
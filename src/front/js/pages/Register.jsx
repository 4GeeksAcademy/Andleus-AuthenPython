import React, { useContext, useEffect, useState } from "react";
import { Context } from "../store/appContext";
import { Navigate } from "react-router-dom";



export const Register = () => {
    const { store, actions } = useContext(Context);
    const [ email, setEmail ] = useState("");
    const [ password, setPassword ] = useState("");
    
    // setEmailLogin("test");
    // setPasswordLogin("pass");


    const handleOnClick = async () => {
        const url = process.env.BACKEND_URL + "/api/signup";
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
            console.log(data);
            const msg = document.querySelector("#allDoneMessage");
            const btn = document.querySelector("#send");
            btn.disabled = true;
            msg.style.display = "block";
            setTimeout(() => {
                window.location.href = "/login"
            }, 2000)
        }else{
            // const msg = document.querySelector("#errorMessage");
            // msg.style.display = "block";
            // setTimeout(() => {
                // msg.style.display = "none";
            // }, 3000)
            console.log(" Falló...", response.status, response.statusText)
        }


    }


    // useEffect(() => {
    //     console.log(emailLogin)
    //     console.log(passwordLogin)
    // }, [emailLogin, passwordLogin])


    return (
        store.isLoggedIn ? <Navigate to="/login"/>:
        <div>

            <div className="col-md-6 py-5 px-md-5">
                <h1 className="text-center">THIS IS REGISTER</h1>
                <p id="allDoneMessage" className="p-3" style={{color: "green", borderRadius: "10px", border: "solid green 3px", display: "none"}}>Register completed</p>
                {/* <p id="errorMessage" className="p-3" style={{color: "red", borderRadius: "10px", border: "solid red 3px", display: "none"}}>The pass or user doesn't exists</p> */}
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
                    <button id="send" onClick={handleOnClick} type="button" className="btn btn-primary btn-block mb-4">
                        Sign up
                    </button>
                </div>
            </div>


        </div>

    )


}
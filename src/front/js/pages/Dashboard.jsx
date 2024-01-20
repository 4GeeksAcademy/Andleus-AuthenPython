import React, {useContext, useState, useEffect} from "react";
import { Navigate } from "react-router-dom";
import { Context } from "../store/appContext";


export const Dashboard = () => {

    const { store, actions } = useContext(Context);
    const [ users, setUsers ] = useState([]);

    useEffect(() => {
        const getAllUsers = async () => {
            try{

                const response = await fetch(process.env.BACKEND_URL+"/api/allUsers", {
                    headers: {
                        Authorization: `Bearer ${localStorage.getItem("token")}`
                    }
                });

                if(response.ok){
                    const data = await response.json();
                    setUsers(data);
                }else{
                    if(response.status === 401){
                        alert("The token has expired, login out...");
                        handleLogout();
                    }else{
                        console.log("Can't not be possible to get the users -> ",response.statusText);
                    }
                }


            }catch (error) {
                console.log("Can't not be possible to get the users -> ",error);
            }
        }

        getAllUsers();

    }, [])



    const handleLogout = () => {
        actions.logout();
    };


    


    return (
        !store.isLoggedIn ? <Navigate to="/login"/>:
        <div className="card-body py-5 px-md-5">
            <div>
                <button type="button" onClick={handleLogout} className="btn btn-primary btn-block mb-4">Logout</button>
            </div>
            <h1>A TABLE</h1>
            <table className="table table-striped">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>EMAIL</th>
                    </tr>
                </thead>
                <tbody>
                    {users.map(user => (
                        <tr key={user.id}>
                            <td>{user.id}</td>
                            <td>{user.email}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>

    )

}
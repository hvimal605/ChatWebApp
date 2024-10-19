import axios from 'axios';
import React, { useState } from 'react'
import { RiLogoutBoxLine } from "react-icons/ri";
 import Cookies from 'js-cookie'
import toast from 'react-hot-toast';

const Logout = () => {
  
  const [loading, setLoading ] = useState(false)
  const handleLogout =async()=>{
    setLoading(true)
    try{ 

     const res = await axios.post("http://localhost:3000/api/user/logout");
     localStorage.removeItem("Chatapp")
     Cookies.remove("harshcookie")
     setLoading(false)
     toast.success("logged out successfully")
     window.location.reload();
     
    }
    catch(error){
   console.log('Error in logout',error)
   toast.error("Error in logging out")
    }

  }
  return (
    <div className='  '>
        <button onClick={handleLogout}
        className=' hover:bg-slate-200  hover:scale-105 duration-200 p-2 rounded-full mr-1'><RiLogoutBoxLine className=' text-3xl' /></button>
        
    </div>
  )
}

export default Logout
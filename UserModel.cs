namespace CodeHack_Jwt_authentication
{
    public class UserModel
    {
        public string Username { get; set; }
        public string Email { get; set; }
        
        //This is just Mock data: Assuming you featch data from Identity Providers
        public UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = null;

            //Validate the User Credentials    
            //Demo Purpose, I have Passed HardCoded User Information    
            if (login.Username == "CodeHack_with_arun")
            {
                user = new UserModel { Username = "CodeHack_with_arun", Email = "codehack.witharun@gmail.com" };
            }
            return user;
        }
    }
}
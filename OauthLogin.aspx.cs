using Microsoft.BingAds;
using Microsoft.BingAds.V12.CustomerManagement;
//using Microsoft.BingAds.V12.Reporting;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;


namespace bingauth
{
    public partial class _Default : Page
    {

        public readonly ExampleBase[] _examples =
        {
            //new ReportRequests(),
        };

        public AuthorizationData _authorizationData;
        public ServiceClient<ICustomerManagementService> _customerService;
        public string ClientState = "ClientStateGoesHere";
        public string ClientId = Convert.ToString(ConfigurationManager.AppSettings["ClientId"]);
        public string DeveloperToken = Convert.ToString(ConfigurationManager.AppSettings["DeveloperToken"]);
        public string RefreshToken = Convert.ToString(ConfigurationManager.AppSettings["RefreshToken"]);

        public const int ClientAccountId = 0;

        

        protected void Page_Load(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(Convert.ToString(Request.QueryString["code"])))
            {
                try
                {
                    Authentication authdata = getaccesstoken(Convert.ToString(Request.QueryString["code"]));

                    SetAuthorizationDataAsync(authdata).Wait();


                    ManageClient manageClient = new ManageClient();

                    manageClient.RunAsync(_authorizationData);
                }
                catch (Exception ex) { }
            }
            else
            {
                generatecode();
            }
        }


        public Authentication getaccesstoken(string code)
        {
            string ClientSecret = "****************";

            var oAuthWebAuthCodeGrant = new OAuthWebAuthCodeGrant(ClientId, ClientSecret, new Uri("http://localhost:52713/Default"), null);
            //var oAuthDesktopMobileAuthCodeGrant = new OAuthDesktopMobileAuthCodeGrant(ClientId);

            oAuthWebAuthCodeGrant.State = "ClientStateGoesHere";
            string refreshToken;

            if (GetRefreshToken(out refreshToken))
            {
                oAuthWebAuthCodeGrant.RequestAccessAndRefreshTokensAsync(refreshToken).Wait();
            }
            else
            {
                oAuthWebAuthCodeGrant.RequestAccessAndRefreshTokensAsync(Request.Url).Wait();
            }

            oAuthWebAuthCodeGrant.NewOAuthTokensReceived +=
                (sender, args) => SaveRefreshToken(args.NewRefreshToken);

            return oAuthWebAuthCodeGrant;
        }

        public void generatecode()
        {
            //var oAuthDesktopMobileAuthCodeGrant = new OAuthDesktopMobileAuthCodeGrant(ClientId);

            string ClientSecret = "*****************";

            var oAuthWebAuthCodeGrant = new OAuthWebAuthCodeGrant(ClientId, ClientSecret, new Uri("http://localhost:52713/Default"), null);


            // It is recommended that you specify a non guessable 'state' request parameter to help prevent
            // cross site request forgery (CSRF). 
            oAuthWebAuthCodeGrant.State = "ClientStateGoesHere";

            Response.Redirect(oAuthWebAuthCodeGrant.GetAuthorizationEndpoint().ToString());
        }

        public bool GetRefreshToken(out string refreshToken)
        {
            var protectedToken = RefreshToken;

            if (string.IsNullOrEmpty(protectedToken))
            {
                refreshToken = null;
                return false;
            }

            try
            {
                refreshToken = protectedToken;
                return true;
            }
            catch (CryptographicException)
            {
                refreshToken = null;
                return false;
            }
            catch (FormatException)
            {
                refreshToken = null;
                return false;
            }
        }

        public Task<OAuthTokens> AuthorizeWithRefreshTokenAsync(OAuthDesktopMobileAuthCodeGrant authentication, string refreshToken)
        {
            return authentication.RequestAccessAndRefreshTokensAsync(refreshToken);
        }

        public void SaveRefreshToken(string newRefreshtoken)
        {
            if (newRefreshtoken != null)
            {
                RefreshToken = newRefreshtoken.Protect();
                // Settings.Default.Save();
            }
        }

        public async Task<AuthorizationData> SetAuthorizationDataAsync(Authentication authentication)
        {
            _authorizationData = new AuthorizationData
            {
                Authentication = authentication,
                DeveloperToken = (DeveloperToken != null) ? DeveloperToken : null
            };

            
            ApiEnvironment environment = ((OAuthWebAuthCodeGrant)_authorizationData.Authentication).Environment;

            CustomerManagementExampleHelper CustomerManagementExampleHelper =
                   new CustomerManagementExampleHelper(null);
            CustomerManagementExampleHelper.CustomerManagementService =
                new ServiceClient<ICustomerManagementService>(_authorizationData, environment);


            var getUserResponse = await CustomerManagementExampleHelper.GetUserAsync(null, true);
            var user = getUserResponse.User;

            var predicate = new Predicate
            {
                Field = "UserId",
                Operator = PredicateOperator.Equals,
                Value = user.Id.ToString()
            };

            var paging = new Paging
            {
                Index = 0,
                Size = 10
            };


            var accounts = (await CustomerManagementExampleHelper.SearchAccountsAsync(
                    new[] { predicate },
                    null,
                    paging)).Accounts.ToArray();

            //var accounts = await SearchAccountsByUserIdAsync(user.Id);
            if (accounts.Length <= 0) return null;

            _authorizationData.AccountId = (long)accounts[0].Id;
            _authorizationData.CustomerId = (int)accounts[0].ParentCustomerId;

            return _authorizationData;
        }
        
    }


    public static class StringProtection
    {
        public static string Protect(this string sourceString)
        {
            var sourceBytes = Encoding.Unicode.GetBytes(sourceString);

            var encryptedBytes = ProtectedData.Protect(sourceBytes, null, DataProtectionScope.CurrentUser);

            return Convert.ToBase64String(encryptedBytes);
        }

        public static string Unprotect(this string protectedString)
        {
            var protectedBytes = Convert.FromBase64String(protectedString);

            var unprotectedBytes = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);

            return Encoding.Unicode.GetString(unprotectedBytes);
        }
    }
    
}

class KVParser:
    def __init__(self, args):
        self.args = {}
        
        for arg in args.split("&"):
            key, value = arg.split("=")
            self.args[key] = value
    
    def get(self, key):
        return self.args[key]
        
    def to_string(self):
        chunks = []
        for key in self.args:
            chunks.append(f"{key}={self.args[key]}&")
        result = "".join(chunks)
        return result[:-1] # removes fencepost &
        
        
    @classmethod
    def profile_for(cls, email_address):
        sanitized = KVParser.sanitize_email(email_address)
        uid = 10
        role = "user"
        
        return KVParser(f"email={sanitized}&uid={uid}&role={role}")
        
        
        
    @classmethod    
    def sanitize_email(cls, email_adress):
        """ Returns the email address with "=" and "&" characters
        removed. """
        chunks = []
        for c in email_adress:
            if c is not "&" and c is not "=":
                chunks.append(c)
                
        result = "".join(chunks)
        return result
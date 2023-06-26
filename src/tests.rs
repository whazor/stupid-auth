#[cfg(test)]
mod test {

use argon2::{
    password_hash::{
        PasswordHash, PasswordVerifier
    },
    Argon2
};

    use rocket::{http::{Status, ContentType}, local::blocking::Client};
    #[derive(Debug)]
    struct HTMLParser<'a> {
        dom: tl::VDom<'a>,
        main_node: tl::HTMLTag<'a>,
    }
    
    impl<'a> HTMLParser<'a> {
        pub fn new(input: &'a str) -> Self {
            let error = "Failed to parse HTML";
            let dom = tl::parse(input, tl::ParserOptions::default()).expect(error);
            let main_handle = dom.query_selector("html").expect(error).next().expect(error);
            let main_node = main_handle.get(dom.parser()).expect(error).as_tag().expect(error).clone();
            Self {
                dom,
                main_node,
            }
        }
        pub fn find_child(
            &self,
            input: tl::HTMLTag,
            selector: &str
        ) -> tl::HTMLTag {
            // let error = format!("Failed to find child with selector: {}", selector).clone().as_str();
            let binding = format!("Failed to find child with selector: {}", selector);
            let error = binding.as_str();
            let node_handle = 
                input.query_selector(self.dom.parser(), selector).expect(error)
                .next().expect(error);
            node_handle.get(self.dom.parser()).expect(error).as_tag().expect(error).clone()
        }
        pub fn find(
            &self,
            selector: &str
        ) -> tl::HTMLTag {
            self.find_child(self.main_node.clone(), selector)
        }
        pub fn get_attribute(
            input: tl::HTMLTag,
            attribute: &str
        ) -> String {
            let binding = format!("Failed to find attribute: {}", attribute);
            let error = binding.as_str();
            let raw: &tl::Bytes<'_> = input.attributes().get(attribute).expect(error).expect(error);
            raw.try_as_utf8_str().expect("attribute not utf8").to_string()
        }
    }

    #[test]
    fn hello_world() {
        let client = Client::tracked(crate::rocket()).expect("valid rocket instance");
        let response = client.get(uri!(crate::index)).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), "Hello, world!");
    }

    #[test]
    fn tutorial() {
        let client = Client::tracked(crate::rocket()).expect("valid rocket instance");
        let response = client.get(uri!(crate::tutorial)).dispatch();
        assert_eq!(response.status(), Status::Ok);
        
        let output = response.into_string().expect("valid string");
        assert!(output.contains("Create your first user by filling in the following fields"));
        
        let parser = HTMLParser::new(&output);

        let form = parser.find("form");
        parser.find_child(form.clone(), "input[name=username]");
        parser.find_child(form.clone(), "input[name=password][type=password]");
        parser.find_child(form.clone(), "button[type=submit]");

        let url = HTMLParser::get_attribute(form.clone(), "action");
        assert_eq!(url, "&#x2F;tutorial");
        let method = HTMLParser::get_attribute(form, "method");
        assert_eq!(method, "POST");
    }

    #[test]
    fn tutorial_genconfig() {
        let client = Client::tracked(crate::rocket()).expect("valid rocket instance");
        let response = client.post(uri!(crate::tutorial_genconfig))
            .header(ContentType::Form)
            .body("username=foo&password=bar")
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let output = response.into_string().expect("valid string");
        assert!(output.contains("Your config file is ready!"));
        let parser = HTMLParser::new(&output);
        let code = parser.find("pre");
        let text = code.children().all(parser.dom.parser()).first().expect("valid child");
        let code = text.as_raw().expect("valid raw").as_utf8_str().into_owned();
        let decoded = code
            .replace("&#x2F;", "/")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&");

        
        let config: serde_yaml::Value = serde_yaml::from_str(&decoded).expect("valid yaml");
        let users = config["users"].as_sequence().expect("valid sequence");
        assert_eq!(users.len(), 1);
        let user = &users[0];
        assert_eq!(user["username"], "foo");
        let hash = user["password"].as_str().expect("valid string").trim();
        let parsed_hash = PasswordHash::new(hash).expect("valid hash");
        let argon2 = Argon2::default();
        
        argon2.verify_password("bar".as_bytes(), &parsed_hash).expect("valid password");
    }
}

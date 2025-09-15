Cloudflare Turnstile Solver (reverse, fully request-based)
-
### !!! THIS IS NOT UP-TO-DATE AND WAS RELEASED ONLY FOR LEARNING PURPOSES !!!
### Why this release
Source code is being shared around so we expect Cloudflare to finally update (no important updates that affect reverses for almost 3 months now) after this release (please)  
Obviously, our service ([solv.now](https://solv.now)) will stay up, although it will probably have downtime for some time.  

P.S: This is a clone but stripped version of our solver from June 2025.  
### Q/A
- Will you provide support/help
  - No
- Solver is flagged!
  - Very sad to hear
- Where is WAF?
  - Removed
- Can I host an API with this code?
  - We do not provide any code, but you surely can if you're smart enough.
- Code sucks!
  - I know, this was my first big project in Rust, as well as my first VM reverse.  
    (if it works, it works heh)
### Credits
[mciem](https://github.com/mciem): everything JS-related (deobfuscator, js parser) and parts of payload  
[mune](https://github.com/munew): everything else (vm, payload, solver itself)
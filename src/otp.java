@RequestMapping(value = "/account/otp.do")

public String otp (
    @ModelAttribute("searchVO") LoginVO searchVO,
    RedirectAttributes redirectAttributes,
    HttpServletRequest request,
    ModelMap model) throws Exception{

    byte[] buffer = new byte[5 + 5 * 5];
    new Random().nextBytes(buffer);
    Base32 codec = new Base32();
    byte[] secretKey = Arrays.copyOf(buffer, 10);
    byte[] bEncodedKey = codec.encode(secretKey);

    String encodedKey = new String(bEncodedKey);

    String QrUrl = getQRBarcodeURL("admin", "facbank", encodedKey);

    model.addAttribute("encodedKey", encodedKey);
    model.addAttribute("QrUrl", QrUrl);

    return "tiles:bsite/account/login/otp";
        }
    public static String getQRBarcodeURL(String user, String host, String secret){
    String format = "";

    return String.format(format, user, host, secret);

    }
}

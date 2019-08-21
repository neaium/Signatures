package service;

import com.KGitextpdf.text.DocumentException;
import com.KGitextpdf.text.Image;
import com.KGitextpdf.text.pdf.BaseFont;
import com.kinggrid.pdf.KGPdfHummer;
import com.kinggrid.pdf.SignatureInter;
import com.kinggrid.pdf.executes.*;
import org.kg.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import static com.KGitextpdf.text.pdf.BaseFont.*;
import static com.itextpdf.text.pdf.BaseFont.COURIER;


/**
 * Created by Neaium on 2019/8/19.
 *
 * @author Neaium
 */
public class testImpl {
    public static void main(String[] args) {
        //添加数字签名
        //digitalSignatures();
        //删除数字签名
        //testDelDigitalSignatures();
        //查看数字证书信息
        //testDigitalcertificates();
        //验证数字签名
        //testVerifyDigitalSignatures();
        //加密机加密卡
        //testDigitalSignaturesSmartCard();
        //添加电子签章
        testElectronicSeal();
        //添加公安版电子签章
        //testElectronicSeal1();
        //电子签章信息
        //testElectronicSealDetails();
        //添加水印
        //testWatermark();

    }

    public static void digitalSignatures() {
        KGPdfHummer hummer = null;
        FileInputStream cert = null;
        FileOutputStream fileOutputStream = null;
        try {
            cert = new FileInputStream("F:/neaium's project/test/key/345.pfx");
            fileOutputStream = new FileOutputStream("G:/印章子系统/test2.pdf");
            hummer = KGPdfHummer.createSignature("G:/印章子系统/test.pdf", null,
                    true, fileOutputStream, new File("G:/印章子系统/"), true);
            hummer.setCertificate(cert, "123", "123");

            PdfSignature4KG pdfSignature4KG = new PdfSignature4KG(
                    "F:/neaium's project/test/key/iSignature.key", 0, "123456");
            pdfSignature4KG.setText("强制");

            hummer.setPdfSignature(pdfSignature4KG);
            hummer.doSignature();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                cert.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                fileOutputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            if (hummer != null) {
                hummer.close();
            }
        }
    }

    public static void testDelDigitalSignatures() {
        KGPdfHummer hummer = null;
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream("G:/印章子系统/test2.pdf");
            hummer = KGPdfHummer.createInstance("G:/印章子系统/test.pdf", null,
                    true, fileOutputStream, true);

            DeleteSignature deleteSignature = new DeleteSignature();
            hummer.addExecute(deleteSignature);

            hummer.doExecute();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                fileOutputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

            if (hummer != null) {
                hummer.close();
            }
        }
    }

    public static void testDigitalcertificates() {
        KGPdfHummer hummer = null;
        try {
            hummer = KGPdfHummer.createInstance("G:/印章子系统/test2.pdf", null, true);
            List<Certificate> certificates = hummer.getSignatureCertificates();
            for (Certificate certificate : certificates) {
                X509Certificate x509Certificate = (X509Certificate) certificate;
                System.out.println(x509Certificate.getSubjectDN().getName());
                System.out.println(x509Certificate.getIssuerDN().getName());
                System.out.println(x509Certificate.getSigAlgName());
                System.out.println(x509Certificate.getVersion());
                System.out.println(x509Certificate.getType());
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (hummer != null) {
                hummer.close();
            }
        }
    }

    public static void testVerifyDigitalSignatures() {
        KGPdfHummer hummer = null;
        try {
            hummer = KGPdfHummer.createInstance("G:/印章子系统/test2.pdf", null, true);
            /*  -1：文档不存在数字签名。
                0：至少有一个签名是无效的。
				1：所有签名有效。
				2：所有签名有效，最后一次签名后追加了内容。
			 */
            System.out.println(hummer.verifySignatures());
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (hummer != null) {
                hummer.close();
            }
        }
    }

    public static void testDigitalSignaturesSmartCard() {
        KGPdfHummer hummer = null;
        FileInputStream cert = null;
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream("G:/印章子系统/test2.pdf");
            cert = new FileInputStream("F:/neaium's project/test/key/345.pfx");
            byte[] certb = new byte[cert.available()];
            cert.read(certb);

            hummer = KGPdfHummer.createSignature("G:/印章子系统/test.pdf", null, true,
                    fileOutputStream, new File("G:/印章子系统/"), true);

			/*-------------------------------第一步：设置证书开始---------------------------------*/
            //模拟加密机、加密槽
            Security.addProvider(new BouncyCastleProvider());
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(new ByteArrayInputStream(certb), "123456".toCharArray());
            String alias = (String) ks.aliases().nextElement();
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, "123456".toCharArray());
            final Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey);

            X509Certificate x509Certificate = (X509Certificate) ks.getCertificate(alias);
            // 公钥证书
			/*CertificateFactory factory = CertificateFactory.getInstance("X.509");
			X509Certificate x509Certificate = (X509Certificate)factory.generateCertificate(
					new FileInputStream("resources/sign.cer"));*/

            hummer.setCertificate(x509Certificate, new SignatureInter() {

                @Override
                public String getEncryptionAlgorithm() {
                    return "RSA";
                }

                @Override
                public String getHashAlgorithm() {
                    return "SHA-1";
                }

                @Override
                public byte[] sign(byte[] message)
                        throws GeneralSecurityException {
                    signature.update(message);
                    return signature.sign();
                }

            });
			/*-------------------------------第一步：设置证书结束---------------------------------*/

            PdfSignature4KG pdfSignature4KG = new PdfSignature4KG(
                    "F:/neaium's project/test/key/iSignature.key", 1, "123456");
            pdfSignature4KG.setText("金格科技");

            hummer.setPdfSignature(pdfSignature4KG);
            hummer.doSignature();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                fileOutputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                cert.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            if (hummer != null) {
                hummer.close();
            }
        }
    }


    public static void testElectronicSeal() {
        KGPdfHummer hummer = null;
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream("G:/印章子系统/test2.pdf");
            hummer = KGPdfHummer.createInstance("G:/印章子系统/test.pdf", null,
                    true, fileOutputStream, true);

            PdfElectronicSeal4KG pdfElectronicSeal4KG = new PdfElectronicSeal4KG(
                    "F:/neaium's project/test/key/iSignature.key", 0, "123456");
            pdfElectronicSeal4KG.setText("强制");

            hummer.addExecute(pdfElectronicSeal4KG);
            hummer.doExecute();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                fileOutputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }

    public static void testElectronicSeal1() {
        KGPdfHummer hummer = null;
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream("G:/印章子系统/test2.pdf");
            hummer = KGPdfHummer.createInstance("G:/印章子系统/test.pdf", null,
                    true, fileOutputStream, true);
            PdfElectronicSeal4GA pdfElectronicSeal4GA = new PdfElectronicSeal4GA("http://192.168.0.90:8080/iSignatureServer/OfficeServer.jsp", "测试3 999999999999999993", "123456", "测试3公章");
            pdfElectronicSeal4GA.setText("金格科技");
            hummer.addExecute(pdfElectronicSeal4GA);
            hummer.doExecute();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                fileOutputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            if (hummer != null) {
                hummer.close();
            }
        }
    }

    public static void testElectronicSealDetails() {
        KGPdfHummer hummer = null;
        try {
            hummer = KGPdfHummer.createInstance("G:/印章子系统/test.pdf", null, true);

            PdfElectronicSealDetails pdfElectronicSealDetails =
                    new PdfElectronicSealDetails();
            hummer.addExecute(pdfElectronicSealDetails);
            hummer.doExecute();

            List<PdfElectronicSealDetails.Signinfo> signinfos = pdfElectronicSealDetails.getSeals();
            for (PdfElectronicSealDetails.Signinfo signinfo : signinfos) {
                System.out.println(signinfo.getKeySn());
                System.out.println(signinfo.getUserName());
                System.out.println(signinfo.getCompName());
                System.out.println(signinfo.getSignSn());
                System.out.println(signinfo.getSignName());
                System.out.println(signinfo.getSignTime());
                System.out.println("左下角：" + signinfo.getRect().getLeft() + " " +
                        signinfo.getRect().getBottom() +

                        "右上角：" + signinfo.getRect().getRight() + " " +
                        signinfo.getRect().getTop());
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (hummer != null) {
                hummer.close();
            }
        }
    }

    public static void testWatermark() {
        KGPdfHummer hummer = null;
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream("G:/印章子系统/test3.pdf");
            hummer = KGPdfHummer.createInstance("G:/印章子系统/test.pdf", null, true,
                    fileOutputStream, true);

            PdfWatermark pdfWatermark = new PdfWatermark();
            //中文编码未解决
            BaseFont baseFont=BaseFont.createFont(COURIER,"UTF-8",true);
            pdfWatermark.setText("widhapodjasdjk;asdlkasjdla/.,;''[[ksj中文dlkajsdl中文");
            Image image=Image.getInstance("key/logo.jpg");
           // pdfWatermark.setImage(image);
            pdfWatermark.setBaseFont(baseFont);
            pdfWatermark.setWatermarkName("中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文");

            hummer.addExecute(pdfWatermark);
            hummer.doExecute();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (DocumentException e) {
            e.printStackTrace();
        }
    }
}

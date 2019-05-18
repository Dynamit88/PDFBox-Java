import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.imageio.ImageIO;

import pdf.pdfbox.pdmodel.PDDocument;
import pdf.pdfbox.rendering.ImageType;
import pdf.pdfbox.rendering.PDFRenderer;

public class main {
	private final static String OUTPUT_DIR = "";
	private static DateFormat dateFormat = new SimpleDateFormat("HH-mm-ss");
	private static Date date = new Date();

	/**
	 * Using PDF renderer
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		PDFBox2();
	}

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	/**
	 * WOrks well
	 * also try loading throug dependency:
	 * http://qaru.site/questions/683827/pdfbox-convert-pdf-to-image-byte
	 */
	private static void PDFBox2() {
		try {
			File pdfFile = new File("blueprint.pdf");
			PDDocument document = PDDocument.load(pdfFile);
			PDFRenderer pdfRenderer = new PDFRenderer(document);

			BufferedImage bim = pdfRenderer.renderImageWithDPI(0, 300, ImageType.RGB);
			File outputfile = new File(OUTPUT_DIR + pdfFile.getName() + "_" + dateFormat.format(date) + ".png");
			ImageIO.write(bim, "png", outputfile);
			
			document.close();
			System.out.println("Image saved at -> " + outputfile.getAbsolutePath());
		} catch (IOException e) {
			System.err.println("Exception while trying to create pdf document - " + e);
		}

	}


	
	
	
	
	public static void PDFtoSVG() {
//		PDDocument document = PDDocument.load( pdfFile );
//		DOMImplementation domImpl =
//		    GenericDOMImplementation.getDOMImplementation();
//
//		// Create an instance of org.w3c.dom.Document.
//		String svgNS = "http://www.w3.org/2000/svg";
//		Document svgDocument = domImpl.createDocument(svgNS, "svg", null);
//		SVGGeneratorContext ctx = SVGGeneratorContext.createDefault(svgDocument);
//		ctx.setEmbeddedFontsOn(true);
//
//		// Ask the test to render into the SVG Graphics2D implementation.
//
//		    for(int i = 0 ; i < document.getNumberOfPages() ; i++){
//		        String svgFName = svgDir+"page"+i+".svg";
//		        (new File(svgFName)).createNewFile();
//		        // Create an instance of the SVG Generator.
//		        SVGGraphics2D svgGenerator = new SVGGraphics2D(ctx,false);
//		        Printable page  = document.getPrintable(i);
//		        page.print(svgGenerator, document.getPageFormat(i), i);
//		        svgGenerator.stream(svgFName);
//		    }
		
		
	}
	
	
	/**
	 * Untested
	 */
	private static void PDFBox4() {
//		InputStream is = getClass().getClassLoader().getResourceAsStream("example.pdf");
//
//		PDDocument pdf = PDDocument.load( is, true );
//		List<PDPage> pages = pdf.getDocumentCatalog().getAllPages();
//
//		for ( PDPage page : pages )
//		{
//		    BufferedImage image = page.convertToImage();
//		}
		
	}
	
	/**
	 * Untested
	 */
	private static void PDFBox3() {
//		String destinationImageFormat = "jpg";
//		boolean success = false;
//		InputStream is = getClass().getClassLoader().getResourceAsStream("example.pdf");
//		PDDocument pdf = PDDocument.load( is, true );
//
//		int resolution = 256;
//		String password = "";
//		String outputPrefix = "myImageFile";
//
//		PDFImageWriter imageWriter = new PDFImageWriter();    
//
//		success = imageWriter.writeImage(pdf, 
//		                    destinationImageFormat, 
//		                    password, 
//		                    1, 
//		                    2, 
//		                    outputPrefix, 
//		                    BufferedImage.TYPE_INT_RGB, 
//		                    resolution);
		
	}
	
	
	
	/**
	 * DOesn't work beacause method does'nt exist
	 */
	private static void PDFBox() {
//		try {
//			String sourceDir = "blueprint.pdf";
//			String destinationDir = "C:/Desktop/";
//			File sourceFile = new File(sourceDir);
//			File destinationFile = new File(destinationDir);
//			if (!destinationFile.exists()) {
//				destinationFile.mkdir();
//				System.out.println("Folder Created -> " + destinationFile.getAbsolutePath());
//			}
//			if (sourceFile.exists()) {
//				PDDocument document = PDDocument.load(sourceFile);
//
//				PDPage page = document.getPage(0);
//
//			
//
////				@SuppressWarnings("unchecked")
////				List<PDPage> list = document.getDocumentCatalog().getAllPages();
////
////				String fileName = sourceFile.getName().replace(".pdf", "");
////				int pageNumber = 1;
////				for (PDPage page : list) {
////					BufferedImage image = page.convertToImage();
////					File outputfile = new File(destinationDir + fileName + "_" + pageNumber + ".png");
////					ImageIO.write(image, "png", outputfile);
////					pageNumber++;
////				}
////				document.close();
////				
//
//				System.out.println("Image saved at -> " + destinationFile.getAbsolutePath());
//			} else {
//				System.err.println(sourceFile.getName() + " File does not exist");
//			}
//
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
	}

}

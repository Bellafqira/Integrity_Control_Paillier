from abc import ABC, abstractmethod
import numpy as np
from src.utils.paillier_context import PaillierContext


class AbstractWatermarkingScheme(ABC):
    """
    Abstract Base Class (Interface) for a watermarking scheme.

    This corresponds to the user's 'Watermark' class request.
    It defines the common methods (embed, extract, etc.) and
    attributes that all watermarking schemes must implement.
    """

    def __init__(self, paillier_context: PaillierContext):
        """
        Initializes the scheme with a shared Paillier context.

        Args:
            paillier_context (PaillierContext): The crypto engine.
        """
        self.paillier = paillier_context

        # Common attributes as requested
        self.host_data = None
        self.watermarked_data = None
        self.secret_key = None  # e.g., a signature key or a QIM key

    @abstractmethod
    def generate_watermark(self, *args, **kwargs) -> object:
        """
        Generates the watermark content (e.g., bit list, signature).

        Returns:
            object: The generated watermark.
        """
        pass

    @abstractmethod
    def embed(self, host_data: np.array, watermark: object) -> np.array:
        """
        Embeds the watermark into the host data.

        Args:
            host_data (np.array): The data to watermark.
            watermark (object): The watermark content to embed.

        Returns:
            np.array: The watermarked data.
        """
        pass

    @abstractmethod
    def extract(self, watermarked_data: np.array) -> object:
        """
        Extracts the watermark from the watermarked data.

        Args:
            watermarked_data (np.array): The data containing the watermark.

        Returns:
            object: The extracted watermark content.
        """
        pass
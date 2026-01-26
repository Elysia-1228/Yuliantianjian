import React from 'react';
import logoImg from '../assets/logo.png';

interface HexLogoProps {
  size?: number;
}

const HexLogo: React.FC<HexLogoProps> = ({ size = 48 }) => {
  return (
    <div style={{ width: size, height: size }} className="relative flex-shrink-0">
      <img 
        src={logoImg} 
        alt="Logo" 
        className="w-full h-full object-contain"
        style={{ filter: 'drop-shadow(0 0 12px rgba(6, 182, 212, 0.6))' }}
      />
    </div>
  );
};

export default HexLogo;
